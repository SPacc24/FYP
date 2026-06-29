from __future__ import annotations
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Any

from storage import scan_store

SCAN_DIR = scan_store.SCANS_DIR


def safe_name(value: str) -> str:
    return ''.join(c if c.isalnum() or c in '._-' else '_' for c in str(value))[:120]


def outfile(prefix: str, host: str, suffix: str) -> Path:
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    return scan_store.scan_path(f'{safe_name(prefix)}_{safe_name(host)}_{ts}.{suffix}')


def which(name: str, alternatives: list[str] | None = None) -> str | None:
    candidates = [name] + (alternatives or [])
    for c in candidates:
        p = shutil.which(c)
        if p:
            return p
    return None


def _as_text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)


def run_cmd(cmd: list[str], output_file: Path | None = None, timeout: int = 300, tool_writes_file: bool = False) -> dict[str, Any]:
    cmd_str = ' '.join(map(str, cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = _as_text(proc.stdout)
        stderr = _as_text(proc.stderr)
        if output_file and not tool_writes_file:
            text_out = stdout
            if stderr:
                text_out += '\n[stderr]\n' + stderr
            try:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(text_out, encoding='utf-8', errors='ignore')
            except OSError as exc:
                return {'success': False, 'status': 'failed', 'command': cmd_str, 'returncode': proc.returncode, 'stdout': stdout, 'stderr': stderr, 'output_file': str(output_file), 'error': f'could not write output file: {exc}'}
        success = proc.returncode == 0
        return {
            'success': success,
            'status': 'success' if success else 'failed',
            'command': cmd_str,
            'returncode': proc.returncode,
            'stdout': stdout,
            'stderr': stderr,
            'output_file': str(output_file or ''),
            'error': '' if success else ((stderr or '').strip() or (stdout or '').strip())[-1000:],
        }
    except subprocess.TimeoutExpired as exc:
        stdout = _as_text(exc.stdout)
        stderr = _as_text(exc.stderr)
        if output_file and not tool_writes_file:
            try:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(stdout + '\n[TIMEOUT]\n' + stderr, encoding='utf-8', errors='ignore')
            except OSError:
                pass
        return {'success': False, 'status': 'failed', 'command': cmd_str, 'returncode': -1, 'stdout': stdout, 'stderr': ('timeout\n' + stderr).strip(), 'output_file': str(output_file or ''), 'error': 'timeout'}
    except FileNotFoundError:
        return {'success': False, 'status': 'failed', 'command': cmd_str, 'returncode': -1, 'stdout': '', 'stderr': 'binary not found', 'output_file': str(output_file or ''), 'error': 'binary not found'}


def completed_empty(result: dict[str, Any], output_file: Path | None = None) -> bool:
    if not result.get('success'):
        return False
    path = output_file or Path(result.get('output_file', ''))
    try:
        return path.exists() and path.stat().st_size == 0
    except Exception:
        return not bool(result.get('stdout'))
