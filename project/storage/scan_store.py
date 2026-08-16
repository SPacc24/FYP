
from __future__ import annotations
import json, os, threading, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parents[1]

def _writable_dir(env_name: str, default: Path, fallback: Path) -> Path:
    configured = os.getenv(env_name)
    candidates = [Path(configured)] if configured else []
    candidates.extend([default, fallback])
    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / '.write_test'
            probe.write_text('ok', encoding='utf-8')
            probe.unlink(missing_ok=True)
            return path
        except OSError:
            continue
    raise PermissionError(f'No writable storage directory found for {env_name}')

RESULTS_DIR = _writable_dir('AUTOPENTEST_RESULTS_DIR', PROJECT_DIR / 'storage' / 'results', Path('/tmp/autopentest/results'))
SCANS_DIR = _writable_dir('AUTOPENTEST_SCANS_DIR', PROJECT_DIR / 'storage' / 'scans', Path('/tmp/autopentest/scans'))
_store: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()

STATUS_QUEUED = 'queued'
STATUS_RUNNING = 'running'
STATUS_SUCCESS = 'success'
STATUS_EMPTY = 'empty'
STATUS_FAILED = 'failed'
STATUS_EXTERNAL_DISCOVERY = 'external_discovery'
STATUS_INTERNAL_DISCOVERY = 'internal_discovery'
STATUS_AWAITING_SUBNET_SELECTION = 'awaiting_subnet_selection'
STATUS_ENTRY_DISCOVERY = 'entry_discovery'
STATUS_LAYER_ENUMERATION = 'layer_enumeration'
STATUS_AWAITING_LAYER_DECISION = 'awaiting_layer_decision'
STATUS_PATH_VERIFICATION = 'path_verification'
STATUS_AWAITING_CONFIGURATION = 'awaiting_assessment_configuration'
STATUS_ASSESSMENT_RUNNING = 'assessment_running'

LABELS = {
    STATUS_QUEUED: 'Queued',
    STATUS_RUNNING: 'Currently Performing',
    STATUS_SUCCESS: 'Completed',
    STATUS_EMPTY: 'No Evidence Observed',
    STATUS_FAILED: 'Incomplete',
    STATUS_EXTERNAL_DISCOVERY: 'External Discovery',
    STATUS_INTERNAL_DISCOVERY: 'Internal Discovery',
    STATUS_AWAITING_SUBNET_SELECTION: 'Awaiting Internal Subnet Selection',
    STATUS_ENTRY_DISCOVERY: 'Entry Discovery',
    STATUS_LAYER_ENUMERATION: 'Current Scope Enumeration',
    STATUS_AWAITING_LAYER_DECISION: 'Awaiting Scope Decision',
    STATUS_PATH_VERIFICATION: 'Path Verification',
    STATUS_AWAITING_CONFIGURATION: 'Awaiting Assessment Configuration',
    STATUS_ASSESSMENT_RUNNING: 'Assessment Running',
}

def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def new_scan(target: str, source_ip: str = '', user_agent: str = '', scan_options: dict[str, Any] | None = None) -> str:
    scan_id = uuid.uuid4().hex[:12]
    with _lock:
        _store[scan_id] = {
            'scan_id': scan_id,
            'target': target,
            'status': 'running',
            'started_at': now(),
            'completed_at': None,
            'source_ip': source_ip,
            'user_agent': user_agent,
            'tasks': [],
            'activity_log': [],
            'audit_log': [],
            'command_log': [],
            'current_task': 'Queued',
            'next_task': '',
            'error': None,
            'scan_options': scan_options or {},
            'results': {},
        }
    return scan_id

def init_tasks(scan_id: str, names: list[str], phase: str = '') -> None:
    with _lock:
        data = _store.get(scan_id)
        if not data: return
        data['tasks'] = [
            {'name': n, 'status': STATUS_QUEUED, 'command': '', 'summary': '', 'phase': phase}
            for n in names
        ]
        data['current_task'] = names[0] if names else ''
        data['next_task'] = names[1] if len(names) > 1 else ''

def append_tasks(scan_id: str, names: list[str], phase: str = '') -> None:
    """Append new phase tasks without removing completed discovery history."""
    with _lock:
        data = _store.get(scan_id)
        if not data:
            return
        existing = {str(task.get('name') or '') for task in data.get('tasks', [])}
        for name in names:
            if name in existing:
                continue
            data.setdefault('tasks', []).append({
                'name': name,
                'status': STATUS_QUEUED,
                'command': '',
                'summary': '',
                'phase': phase,
            })
            existing.add(name)
        queued = [task for task in data.get('tasks', []) if task.get('status') == STATUS_QUEUED]
        if queued:
            data['current_task'] = queued[0]['name']
            data['next_task'] = queued[1]['name'] if len(queued) > 1 else ''

def transition_status(scan_id: str, expected: set[str] | list[str] | tuple[str, ...], new_status: str, **kwargs: Any) -> bool:
    """Atomically move a scan between workflow states."""
    expected_values = set(expected)
    with _lock:
        data = _store.get(scan_id)
        if not data or str(data.get('status') or '') not in expected_values:
            return False
        data['status'] = new_status
        data.update(kwargs)
        return True

def set_task(scan_id: str, name: str, status: str, command: str = '', summary: str = '') -> None:
    with _lock:
        data = _store.get(scan_id)
        if not data: return
        for task in data.get('tasks', []):
            if task['name'] == name:
                task['status'] = status
                if command: task['command'] = command
                if summary: task['summary'] = summary
                break
        running = next((t for t in data['tasks'] if t['status'] == STATUS_RUNNING), None)
        queued = [t for t in data['tasks'] if t['status'] == STATUS_QUEUED]
        data['current_task'] = running['name'] if running else (queued[0]['name'] if queued else 'Enumeration complete')
        data['next_task'] = queued[1]['name'] if (not running and len(queued) > 1) else (queued[0]['name'] if running and queued else '')

def log(scan_id: str, message: str, level: str = 'INFO', command: str = '') -> None:
    entry = {'time': datetime.now(timezone.utc).strftime('%H:%M:%SZ'), 'timestamp': now(), 'level': level, 'message': message, 'command': command}
    with _lock:
        if scan_id in _store:
            _store[scan_id]['activity_log'].append(entry)

def log_command(scan_id: str, *, command: str, purpose: str, output: str = '', output_summary: str = '', status: str = '', exit_code: Any = '', output_file: str = '', output_truncated: bool = False, started_at: str = '', ended_at: str = '', interface: str = '', source_address: str = '', segment_id: str = '', target: str = '') -> None:
    entry = {
        'time': datetime.now(timezone.utc).strftime('%H:%M:%SZ'),
        'timestamp': now(),
        'level': status or 'Completed',
        'status': status or 'Completed',
        'command': command,
        'purpose': purpose,
        'message': purpose,
        'output': output or '',
        'output_summary': output_summary or '',
        'exit_code': exit_code,
        'output_file': output_file or '',
        'output_truncated': bool(output_truncated),
        'started_at': started_at or '',
        'ended_at': ended_at or '',
        'interface': interface or '',
        'source_address': source_address or '',
        'segment_id': segment_id or '',
        'target': target or '',
    }
    with _lock:
        if scan_id in _store:
            _store[scan_id].setdefault('command_log', []).append(entry)
            _store[scan_id]['activity_log'].append(entry)

def audit_event(scan_id: str, actor: str, action: str, details: Any = None) -> None:
    entry = {
        'time': datetime.now(timezone.utc).strftime('%H:%M:%SZ'),
        'timestamp': now(),
        'actor': actor or 'system',
        'action': action or '',
        'details': details if details is not None else {},
    }
    with _lock:
        if scan_id in _store:
            _store[scan_id].setdefault('audit_log', []).append(entry)

def update(scan_id: str, **kwargs: Any) -> None:
    with _lock:
        if scan_id in _store:
            _store[scan_id].update(kwargs)

def get(scan_id: str) -> dict[str, Any] | None:
    with _lock:
        data = _store.get(scan_id)
        return json.loads(json.dumps(data, default=str)) if data else None

def progress(scan_id: str) -> dict[str, Any]:
    data = get(scan_id) or {}
    tasks = data.get('tasks', [])
    total = len(tasks)
    done = sum(1 for t in tasks if t.get('status') in {STATUS_SUCCESS, STATUS_EMPTY, STATUS_FAILED})
    pct = round((done / total) * 100, 1) if total else 0
    data['task_percent'] = pct
    data['task_done'] = done
    data['task_total'] = total
    data['command_log'] = data.get('command_log') or [e for e in data.get('activity_log', []) if e.get('command')]
    return data

def progress_summary(scan_id: str, *, command_limit: int = 60, service_limit: int = 10) -> dict[str, Any]:
    """Return a lightweight live-progress snapshot without copying raw evidence.

    This is intentionally additive: the existing ``progress()`` contract remains
    unchanged for older callers.  The summary is used by the Phase 3 browser
    progress page so large command outputs and full result packages are not
    serialized on every poll.
    """

    def _trim(value: Any, limit: int = 260) -> str:
        text = str(value or '')
        return text if len(text) <= limit else text[: max(0, limit - 3)] + '...'

    with _lock:
        data = _store.get(scan_id)
        if not data:
            snapshot = None
        else:
            tasks = [dict(task) for task in data.get('tasks', []) if isinstance(task, dict)]
            activity = [entry for entry in data.get('activity_log', []) if isinstance(entry, dict)]
            commands = [entry for entry in data.get('command_log', []) if isinstance(entry, dict)]
            if not commands:
                commands = [entry for entry in activity if entry.get('command')]
            results = data.get('results') if isinstance(data.get('results'), dict) else {}

            assessment_tasks = [task for task in tasks if str(task.get('phase') or '') == 'assessment']
            assessment_total = len(assessment_tasks)
            assessment_done = sum(
                1
                for task in assessment_tasks
                if task.get('status') in {STATUS_SUCCESS, STATUS_EMPTY, STATUS_FAILED}
            )
            assessment_percent = (
                round((assessment_done / assessment_total) * 100, 1)
                if assessment_total
                else 0
            )

            total = len(tasks)
            done = sum(
                1
                for task in tasks
                if task.get('status') in {STATUS_SUCCESS, STATUS_EMPTY, STATUS_FAILED}
            )
            task_percent = round((done / total) * 100, 1) if total else 0

            raw_hosts = results.get('hosts') if isinstance(results.get('hosts'), list) else []
            host_values: set[str] = set()
            for host in raw_hosts:
                if isinstance(host, dict):
                    value = str(host.get('ip') or host.get('address') or '').strip()
                else:
                    value = str(host or '').strip()
                if value:
                    host_values.add(value)

            services = results.get('service_inventory') if isinstance(results.get('service_inventory'), list) else []
            tcp_services = [row for row in services if isinstance(row, dict) and str(row.get('protocol') or 'tcp').lower() == 'tcp']
            udp_services = [row for row in services if isinstance(row, dict) and str(row.get('protocol') or '').lower() == 'udp']
            products = {
                str(row.get('product') or '').strip().lower()
                for row in services
                if isinstance(row, dict) and str(row.get('product') or '').strip()
            }
            versioned = [
                row
                for row in services
                if isinstance(row, dict) and str(row.get('version') or '').strip()
            ]
            cves = results.get('cve_matches') if isinstance(results.get('cve_matches'), list) else []

            recent_services = []
            for row in [item for item in services if isinstance(item, dict)][-max(1, int(service_limit)):]:
                recent_services.append({
                    'host': _trim(row.get('host') or row.get('ip') or row.get('address'), 80),
                    'port': row.get('port', ''),
                    'protocol': _trim(row.get('protocol'), 16),
                    'state': _trim(row.get('state'), 40),
                    'service': _trim(row.get('service'), 80),
                    'product': _trim(row.get('product'), 120),
                    'version': _trim(row.get('version'), 100),
                })

            command_start = max(0, len(commands) - max(1, int(command_limit)))
            compact_commands = []
            for index in range(command_start, len(commands)):
                entry = commands[index]
                compact_commands.append({
                    'command_index': index,
                    'time': _trim(entry.get('time'), 32),
                    'timestamp': _trim(entry.get('timestamp'), 64),
                    'status': _trim(entry.get('status') or entry.get('level'), 80),
                    'level': _trim(entry.get('level') or entry.get('status'), 80),
                    'purpose': _trim(entry.get('purpose') or entry.get('message'), 260),
                    'message': _trim(entry.get('message') or entry.get('purpose'), 260),
                    'command': str(entry.get('command') or ''),
                    'output_summary': _trim(entry.get('output_summary'), 320),
                    'exit_code': entry.get('exit_code', ''),
                    'output_file': _trim(entry.get('output_file'), 500),
                    'output_truncated': bool(entry.get('output_truncated')),
                    'started_at': _trim(entry.get('started_at'), 64),
                    'ended_at': _trim(entry.get('ended_at'), 64),
                    'target': _trim(entry.get('target'), 100),
                })

            last_event = activity[-1] if activity else (commands[-1] if commands else {})
            last_update_at = str(last_event.get('timestamp') or data.get('assessment_started_at') or data.get('started_at') or '')

            snapshot = {
                'scan_id': str(data.get('scan_id') or scan_id),
                'target': str(data.get('target') or ''),
                'status': str(data.get('status') or ''),
                'workflow_stage': str(data.get('workflow_stage') or ''),
                'current_task': str(data.get('current_task') or ''),
                'next_task': str(data.get('next_task') or ''),
                'error': str(data.get('error') or ''),
                'started_at': str(data.get('started_at') or ''),
                'assessment_started_at': str(data.get('assessment_started_at') or ''),
                'completed_at': str(data.get('completed_at') or ''),
                'last_update_at': last_update_at,
                'server_timestamp': now(),
                'tasks': tasks,
                'task_done': done,
                'task_total': total,
                'task_percent': task_percent,
                'assessment_task_done': assessment_done,
                'assessment_task_total': assessment_total,
                'assessment_task_percent': assessment_percent,
                'command_log': compact_commands,
                'command_log_total': len(commands),
                'has_saved_results': bool(results),
                'live_findings': {
                    'host_count': len(host_values),
                    'tcp_service_count': len(tcp_services),
                    'udp_service_count': len(udp_services),
                    'product_count': len(products),
                    'versioned_endpoint_count': len(versioned),
                    'cve_reference_count': len(cves),
                    'cve_review_status': _trim(results.get('cve_review_status'), 160),
                    'recent_services': recent_services,
                },
            }

    if snapshot is not None:
        return snapshot

    # Historical scans may not yet be present in memory after a process restart.
    # Loading is only a fallback; active-scan polling uses the lock-protected path
    # above and therefore avoids a deep copy of the full result package.
    loaded = load(scan_id)
    if not loaded:
        return {}
    with _lock:
        present = _store.get(scan_id)
    if present is None:
        return {}
    return progress_summary(scan_id, command_limit=command_limit, service_limit=service_limit)

def result_path(filename: str) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR / filename

def scan_path(filename: str) -> Path:
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    return SCANS_DIR / filename

def storage_path(*parts: str) -> Path:
    path = PROJECT_DIR / 'storage'
    for part in parts:
        path = path / part
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

def persist(scan_id: str) -> str:
    data = get(scan_id) or {}
    path = result_path(f'{scan_id}.json')
    path.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
    return str(path)

def load(scan_id: str) -> dict[str, Any] | None:
    data = get(scan_id)
    if data: return data
    path = result_path(f'{scan_id}.json')
    if path.exists():
        loaded = json.loads(path.read_text(encoding='utf-8'))
        with _lock: _store[scan_id] = loaded
        return loaded
    return None
