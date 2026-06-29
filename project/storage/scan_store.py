
from __future__ import annotations
import json, threading, uuid
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parents[1]
RESULTS_DIR = PROJECT_DIR / 'storage' / 'results'
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
_store: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()

STATUS_QUEUED = 'queued'
STATUS_RUNNING = 'running'
STATUS_SUCCESS = 'success'
STATUS_EMPTY = 'empty'
STATUS_FAILED = 'failed'

LABELS = {
    STATUS_QUEUED: 'Queued',
    STATUS_RUNNING: 'Currently Performing',
    STATUS_SUCCESS: 'Completed',
    STATUS_EMPTY: 'No Evidence Observed',
    STATUS_FAILED: 'Incomplete',
}

def now() -> str:
    return datetime.now().isoformat(timespec='seconds')

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
            'command_log': [],
            'current_task': 'Queued',
            'next_task': '',
            'error': None,
            'scan_options': scan_options or {},
            'results': {},
        }
    return scan_id

def init_tasks(scan_id: str, names: list[str]) -> None:
    with _lock:
        data = _store.get(scan_id)
        if not data: return
        data['tasks'] = [{'name': n, 'status': STATUS_QUEUED, 'command': '', 'summary': ''} for n in names]
        data['current_task'] = names[0] if names else ''
        data['next_task'] = names[1] if len(names) > 1 else ''

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
    entry = {'time': datetime.now().strftime('%H:%M:%S'), 'level': level, 'message': message, 'command': command}
    with _lock:
        if scan_id in _store:
            _store[scan_id]['activity_log'].append(entry)

def log_command(scan_id: str, *, command: str, purpose: str, output: str = '', status: str = '', exit_code: Any = '', output_file: str = '', output_truncated: bool = False) -> None:
    entry = {
        'time': datetime.now().strftime('%H:%M:%S'),
        'level': status or 'Completed',
        'status': status or 'Completed',
        'command': command,
        'purpose': purpose,
        'message': purpose,
        'output': output or '',
        'exit_code': exit_code,
        'output_file': output_file or '',
        'output_truncated': bool(output_truncated),
    }
    with _lock:
        if scan_id in _store:
            _store[scan_id].setdefault('command_log', []).append(entry)
            _store[scan_id]['activity_log'].append(entry)

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

def persist(scan_id: str) -> str:
    data = get(scan_id) or {}
    path = RESULTS_DIR / f'{scan_id}.json'
    path.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
    return str(path)

def load(scan_id: str) -> dict[str, Any] | None:
    data = get(scan_id)
    if data: return data
    path = RESULTS_DIR / f'{scan_id}.json'
    if path.exists():
        loaded = json.loads(path.read_text(encoding='utf-8'))
        with _lock: _store[scan_id] = loaded
        return loaded
    return None
