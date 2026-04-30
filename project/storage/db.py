
"""
project/db.py
MySQL database handler for AutoPenTest.
Handles all storage: scans, operations, technique results, CVE data.
Uses mysql-connector-python.
"""

import json
import logging
from contextlib import closing
from datetime import datetime

import mysql.connector

log = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE DATABASE IF NOT EXISTS autopentest;
USE autopentest;

CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_ip VARCHAR(50) NOT NULL,
    port_range VARCHAR(50) DEFAULT '1-1024',
    os_detected VARCHAR(200) DEFAULT 'Unknown',
    ports_open TEXT,
    raw_json LONGTEXT,
    scan_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    port INT,
    service VARCHAR(100),
    cve_id VARCHAR(50),
    cve_score FLOAT DEFAULT 0.0,
    severity VARCHAR(20),
    description TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS operations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    operation_id VARCHAR(100) UNIQUE,
    operation_name VARCHAR(200),
    state VARCHAR(50),
    agent_host VARCHAR(200),
    agent_paw VARCHAR(100),
    total_techniques INT DEFAULT 0,
    success_count INT DEFAULT 0,
    fail_count INT DEFAULT 0,
    risk_score FLOAT DEFAULT 0.0,
    timed_out TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS technique_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    operation_id VARCHAR(100),
    technique_id VARCHAR(50),
    technique_name VARCHAR(200),
    tactic VARCHAR(100),
    status VARCHAR(20),
    output TEXT,
    command_run TEXT,
    exec_timestamp DATETIME,
    INDEX idx_operation (operation_id)
);
"""


class Database:
    def __init__(self, host: str, user: str, password: str, database: str):
        self.config = {
            'host': host,
            'user': user,
            'password': password,
            'database': database,
        }

    def _connect(self, include_db: bool = True):
        cfg = dict(self.config)
        if not include_db:
            cfg.pop('database', None)
        return mysql.connector.connect(**cfg)

    def _execute_many(self, cursor, statements):
        for statement in statements:
            stmt = statement.strip()
            if stmt:
                cursor.execute(stmt)

    def init_schema(self):
        try:
            with closing(self._connect(include_db=False)) as conn, closing(conn.cursor()) as cursor:
                self._execute_many(cursor, SCHEMA_SQL.strip().split(';'))
                conn.commit()
            log.info('Database schema initialised successfully.')
            return True
        except Exception as e:
            log.error('Schema init failed: %s', e)
            return False

    def test_connection(self):
        try:
            with closing(self._connect()) as conn:
                conn.is_connected()
            return True, 'Connected successfully.'
        except Exception as e:
            return False, str(e)

    def save_scan(self, target_ip: str, scan_results: dict, port_range: str = '1-1024') -> int:
        try:
            ports_open = json.dumps([p.get('port') for p in scan_results.get('ports', [])])
            with closing(self._connect()) as conn, closing(conn.cursor()) as cursor:
                cursor.execute(
                    'INSERT INTO scans (target_ip, port_range, os_detected, ports_open, raw_json) VALUES (%s, %s, %s, %s, %s)',
                    (target_ip, port_range, scan_results.get('os', 'Unknown'), ports_open, json.dumps(scan_results))
                )
                conn.commit()
                scan_id = cursor.lastrowid
            log.info('Scan saved: id=%s target=%s', scan_id, target_ip)
            return scan_id
        except Exception as e:
            log.error('save_scan failed: %s', e)
            return -1

    def get_scan(self, scan_id: int):
        try:
            with closing(self._connect()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
                cursor.execute('SELECT * FROM scans WHERE id = %s', (scan_id,))
                row = cursor.fetchone()
            if row and row.get('raw_json'):
                row['parsed'] = json.loads(row['raw_json'])
            return row
        except Exception as e:
            log.error('get_scan failed: %s', e)
            return None

    def get_recent_scans(self, limit: int = 10):
        try:
            with closing(self._connect()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
                cursor.execute('SELECT id, target_ip, os_detected, scan_time FROM scans ORDER BY scan_time DESC LIMIT %s', (limit,))
                return cursor.fetchall()
        except Exception as e:
            log.error('get_recent_scans failed: %s', e)
            return []

    def save_vulnerabilities(self, scan_id: int, vulns: list) -> bool:
        if not vulns:
            return True
        try:
            with closing(self._connect()) as conn, closing(conn.cursor()) as cursor:
                for v in vulns:
                    cursor.execute(
                        'INSERT INTO vulnerabilities (scan_id, port, service, cve_id, cve_score, severity, description) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                        (scan_id, v.get('port'), v.get('service', ''), v.get('cve_id', 'N/A'), v.get('cve_score', 0.0), v.get('severity', 'Unknown'), v.get('description', ''))
                    )
                conn.commit()
            log.info('Saved %s vulnerabilities for scan %s', len(vulns), scan_id)
            return True
        except Exception as e:
            log.error('save_vulnerabilities failed: %s', e)
            return False

    def get_vulnerabilities(self, scan_id: int):
        try:
            with closing(self._connect()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
                cursor.execute('SELECT * FROM vulnerabilities WHERE scan_id = %s ORDER BY cve_score DESC', (scan_id,))
                return cursor.fetchall()
        except Exception as e:
            log.error('get_vulnerabilities failed: %s', e)
            return []

    def save_operation(self, scan_id: int, op_results: dict, risk_score: float) -> bool:
        try:
            with closing(self._connect()) as conn, closing(conn.cursor()) as cursor:
                cursor.execute(
                    'INSERT INTO operations (scan_id, operation_id, operation_name, state, agent_host, agent_paw, total_techniques, success_count, fail_count, risk_score, timed_out) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE state=VALUES(state), success_count=VALUES(success_count), fail_count=VALUES(fail_count), risk_score=VALUES(risk_score), timed_out=VALUES(timed_out), agent_host=VALUES(agent_host), agent_paw=VALUES(agent_paw), total_techniques=VALUES(total_techniques)',
                    (
                        scan_id, op_results.get('operation_id', ''), op_results.get('operation_name', ''), op_results.get('state', ''), op_results.get('agent_host', ''), op_results.get('agent_paw', ''), op_results.get('total', 0), op_results.get('success_count', 0), op_results.get('fail_count', 0), risk_score, 1 if op_results.get('timed_out') else 0
                    )
                )
                for t in op_results.get('techniques_run', []):
                    ts = None
                    timestamp = t.get('timestamp')
                    if timestamp:
                        try:
                            ts = datetime.fromisoformat(str(timestamp).replace('Z', ''))
                        except Exception:
                            ts = None
                    cursor.execute(
                        'INSERT INTO technique_results (operation_id, technique_id, technique_name, tactic, status, output, command_run, exec_timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
                        (op_results.get('operation_id', ''), t.get('technique_id', 'N/A'), t.get('technique_name', 'Unknown'), t.get('tactic', ''), t.get('status', 'unknown'), (t.get('output', '') or '')[:2000], (t.get('command', '') or '')[:1000], ts)
                    )
                conn.commit()
            log.info('Operation saved: %s', op_results.get('operation_id'))
            return True
        except Exception as e:
            log.error('save_operation failed: %s', e)
            return False

    def get_operation(self, operation_id: str):
        try:
            with closing(self._connect()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
                cursor.execute('SELECT * FROM operations WHERE operation_id = %s', (operation_id,))
                op = cursor.fetchone()
                if op:
                    cursor.execute('SELECT * FROM technique_results WHERE operation_id = %s', (operation_id,))
                    op['techniques'] = cursor.fetchall()
                return op
        except Exception as e:
            log.error('get_operation failed: %s', e)
            return None

    def get_operations_for_scan(self, scan_id: int):
        try:
            with closing(self._connect()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
                cursor.execute('SELECT * FROM operations WHERE scan_id = %s ORDER BY created_at DESC', (scan_id,))
                return cursor.fetchall()
        except Exception as e:
            log.error('get_operations_for_scan failed: %s', e)
            return []
