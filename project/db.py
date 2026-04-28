"""
project/db.py
MySQL database handler for AutoPenTest.
Handles all storage: scans, operations, technique results, CVE data.
Uses mysql-connector-python.

Install: pip3 install mysql-connector-python --break-system-packages
"""

import mysql.connector
import json
import logging
from datetime import datetime

log = logging.getLogger(__name__)


# ── Schema (run this once in MySQL Workbench) ───────────────────────────────
SCHEMA_SQL = """
CREATE DATABASE IF NOT EXISTS autopentest;
USE autopentest;

-- Scan results from Nmap
CREATE TABLE IF NOT EXISTS scans (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    target_ip     VARCHAR(50)  NOT NULL,
    port_range    VARCHAR(50)  DEFAULT '1-1024',
    os_detected   VARCHAR(200) DEFAULT 'Unknown',
    ports_open    TEXT,
    raw_json      LONGTEXT,
    scan_time     DATETIME     DEFAULT CURRENT_TIMESTAMP
);

-- CVE / vulnerability findings from mapping step
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    scan_id       INT          NOT NULL,
    port          INT,
    service       VARCHAR(100),
    cve_id        VARCHAR(50),
    cve_score     FLOAT        DEFAULT 0.0,
    severity      VARCHAR(20),
    description   TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Caldera operation records
CREATE TABLE IF NOT EXISTS operations (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scan_id         INT,
    operation_id    VARCHAR(100) UNIQUE,
    operation_name  VARCHAR(200),
    state           VARCHAR(50),
    agent_host      VARCHAR(200),
    agent_paw       VARCHAR(100),
    total_techniques INT DEFAULT 0,
    success_count    INT DEFAULT 0,
    fail_count       INT DEFAULT 0,
    risk_score       FLOAT DEFAULT 0.0,
    timed_out        TINYINT(1) DEFAULT 0,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

-- Individual technique execution results
CREATE TABLE IF NOT EXISTS technique_results (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    operation_id    VARCHAR(100),
    technique_id    VARCHAR(50),
    technique_name  VARCHAR(200),
    tactic          VARCHAR(100),
    status          VARCHAR(20),
    output          TEXT,
    command_run     TEXT,
    exec_timestamp  DATETIME,
    INDEX idx_operation (operation_id)
);
"""


class Database:
    def __init__(self, host: str, user: str, password: str, database: str):
        self.config = {
            'host':     host,
            'user':     user,
            'password': password,
            'database': database
        }

    def _connect(self):
        return mysql.connector.connect(**self.config)

    # ── Setup ────────────────────────────────────────────────────────────────

    def init_schema(self):
        """
        Create all tables if they don't exist.
        Run this once on first startup.
        """
        try:
            conn   = mysql.connector.connect(
                host=self.config['host'],
                user=self.config['user'],
                password=self.config['password']
            )
            cursor = conn.cursor()
            for statement in SCHEMA_SQL.strip().split(';'):
                stmt = statement.strip()
                if stmt:
                    cursor.execute(stmt)
            conn.commit()
            cursor.close()
            conn.close()
            log.info("Database schema initialised successfully.")
            return True
        except Exception as e:
            log.error(f"Schema init failed: {e}")
            return False

    def test_connection(self) -> tuple[bool, str]:
        """Test if database connection works."""
        try:
            conn = self._connect()
            conn.close()
            return True, "Connected successfully."
        except Exception as e:
            return False, str(e)

    # ── Scans ────────────────────────────────────────────────────────────────

    def save_scan(self, target_ip: str, scan_results: dict, port_range: str = '1-1024') -> int:
        """
        Save Nmap scan results to DB.
        Returns the new scan ID.
        """
        try:
            conn   = self._connect()
            cursor = conn.cursor()

            ports_open = json.dumps([
                p['port'] for p in scan_results.get('ports', [])
            ])

            cursor.execute(
                """INSERT INTO scans
                   (target_ip, port_range, os_detected, ports_open, raw_json)
                   VALUES (%s, %s, %s, %s, %s)""",
                (
                    target_ip,
                    port_range,
                    scan_results.get('os', 'Unknown'),
                    ports_open,
                    json.dumps(scan_results)
                )
            )
            conn.commit()
            scan_id = cursor.lastrowid
            log.info(f"Scan saved: id={scan_id} target={target_ip}")
            cursor.close()
            conn.close()
            return scan_id

        except Exception as e:
            log.error(f"save_scan failed: {e}")
            return -1

    def get_scan(self, scan_id: int) -> dict | None:
        """Retrieve a scan record by ID."""
        try:
            conn   = self._connect()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            if row and row.get('raw_json'):
                row['parsed'] = json.loads(row['raw_json'])
            return row
        except Exception as e:
            log.error(f"get_scan failed: {e}")
            return None

    def get_recent_scans(self, limit: int = 10) -> list:
        """Get the most recent scan records."""
        try:
            conn   = self._connect()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT id, target_ip, os_detected, scan_time FROM scans ORDER BY scan_time DESC LIMIT %s",
                (limit,)
            )
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            return rows
        except Exception as e:
            log.error(f"get_recent_scans failed: {e}")
            return []

    # ── Vulnerabilities ──────────────────────────────────────────────────────

    def save_vulnerabilities(self, scan_id: int, vulns: list) -> bool:
        """
        Save CVE vulnerability findings for a scan.
        Each vuln: {port, service, cve_id, cve_score, severity, description}
        """
        if not vulns:
            return True
        try:
            conn   = self._connect()
            cursor = conn.cursor()
            for v in vulns:
                cursor.execute(
                    """INSERT INTO vulnerabilities
                       (scan_id, port, service, cve_id, cve_score, severity, description)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                    (
                        scan_id,
                        v.get('port'),
                        v.get('service', ''),
                        v.get('cve_id', 'N/A'),
                        v.get('cve_score', 0.0),
                        v.get('severity', 'Unknown'),
                        v.get('description', '')
                    )
                )
            conn.commit()
            cursor.close()
            conn.close()
            log.info(f"Saved {len(vulns)} vulnerabilities for scan {scan_id}")
            return True
        except Exception as e:
            log.error(f"save_vulnerabilities failed: {e}")
            return False

    def get_vulnerabilities(self, scan_id: int) -> list:
        """Get all vulnerability findings for a scan."""
        try:
            conn   = self._connect()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = %s ORDER BY cve_score DESC",
                (scan_id,)
            )
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            return rows
        except Exception as e:
            log.error(f"get_vulnerabilities failed: {e}")
            return []

    # ── Operations ───────────────────────────────────────────────────────────

    def save_operation(self, scan_id: int, op_results: dict, risk_score: float) -> bool:
        """
        Save a completed Caldera operation and all its technique results.
        """
        try:
            conn   = self._connect()
            cursor = conn.cursor()

            # Save operation record
            cursor.execute(
                """INSERT INTO operations
                   (scan_id, operation_id, operation_name, state,
                    agent_host, agent_paw,
                    total_techniques, success_count, fail_count,
                    risk_score, timed_out)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON DUPLICATE KEY UPDATE
                     state=VALUES(state),
                     success_count=VALUES(success_count),
                     fail_count=VALUES(fail_count),
                     risk_score=VALUES(risk_score)""",
                (
                    scan_id,
                    op_results.get('operation_id', ''),
                    op_results.get('operation_name', ''),
                    op_results.get('state', ''),
                    op_results.get('agent_host', ''),
                    op_results.get('agent_paw', ''),
                    op_results.get('total', 0),
                    op_results.get('success_count', 0),
                    op_results.get('fail_count', 0),
                    risk_score,
                    1 if op_results.get('timed_out') else 0
                )
            )

            # Save each technique result
            for t in op_results.get('techniques_run', []):
                ts = None
                if t.get('timestamp'):
                    try:
                        ts = datetime.fromisoformat(t['timestamp'].replace('Z', ''))
                    except Exception:
                        ts = None

                cursor.execute(
                    """INSERT INTO technique_results
                       (operation_id, technique_id, technique_name,
                        tactic, status, output, command_run, exec_timestamp)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        op_results.get('operation_id', ''),
                        t.get('technique_id', 'N/A'),
                        t.get('technique_name', 'Unknown'),
                        t.get('tactic', ''),
                        t.get('status', 'unknown'),
                        t.get('output', '')[:2000],  # cap output length
                        t.get('command', '')[:1000],
                        ts
                    )
                )

            conn.commit()
            cursor.close()
            conn.close()
            log.info(f"Operation saved: {op_results.get('operation_id')}")
            return True

        except Exception as e:
            log.error(f"save_operation failed: {e}")
            return False

    def get_operation(self, operation_id: str) -> dict | None:
        """Get an operation record with all technique results."""
        try:
            conn   = self._connect()
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                "SELECT * FROM operations WHERE operation_id = %s",
                (operation_id,)
            )
            op = cursor.fetchone()

            if op:
                cursor.execute(
                    "SELECT * FROM technique_results WHERE operation_id = %s",
                    (operation_id,)
                )
                op['techniques'] = cursor.fetchall()

            cursor.close()
            conn.close()
            return op
        except Exception as e:
            log.error(f"get_operation failed: {e}")
            return None

    def get_operations_for_scan(self, scan_id: int) -> list:
        """Get all operations linked to a scan."""
        try:
            conn   = self._connect()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT * FROM operations WHERE scan_id = %s ORDER BY created_at DESC",
                (scan_id,)
            )
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            return rows
        except Exception as e:
            log.error(f"get_operations_for_scan failed: {e}")
            return []
