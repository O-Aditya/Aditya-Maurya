"""SQLite storage for audit results and historical trend analysis."""
import sqlite3
import json
import os
from datetime import datetime
from typing import List, Optional
from .models import MachineAudit, Finding


DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "voldebug_audit.db")


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(db_path: str = DB_PATH):
    """Initialize database tables."""
    conn = get_connection(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS audit_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_date TEXT NOT NULL,
            total_machines INTEGER,
            avg_risk_score REAL,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS machine_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            hostname TEXT NOT NULL,
            folder_name TEXT,
            ip_address TEXT,
            os_name TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            critical_findings INTEGER,
            high_findings INTEGER,
            medium_findings INTEGER,
            low_findings INTEGER,
            total_findings INTEGER,
            bitlocker_enabled INTEGER,
            defender_running INTEGER,
            edr_detected INTEGER,
            edr_name TEXT,
            patch_gap_days INTEGER,
            last_patch_date TEXT,
            collection_time TEXT,
            analyzed_at TEXT,
            full_data TEXT,
            FOREIGN KEY (run_id) REFERENCES audit_runs(id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_audit_id INTEGER,
            hostname TEXT,
            severity TEXT,
            category TEXT,
            title TEXT,
            description TEXT,
            remediation TEXT,
            owner TEXT,
            attacker_context TEXT,
            is_compound INTEGER,
            FOREIGN KEY (machine_audit_id) REFERENCES machine_audits(id)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_hostname ON findings(hostname);
        CREATE INDEX IF NOT EXISTS idx_machine_hostname ON machine_audits(hostname);
        CREATE INDEX IF NOT EXISTS idx_machine_run ON machine_audits(run_id);
    """)
    conn.commit()
    conn.close()


def save_audit_run(audits: List[MachineAudit], notes: str = "", db_path: str = DB_PATH) -> int:
    """Save a complete audit run to the database."""
    init_db(db_path)
    conn = get_connection(db_path)

    avg_risk = sum(a.risk_score for a in audits) / len(audits) if audits else 0
    cursor = conn.execute(
        """INSERT INTO audit_runs (run_date, total_machines, avg_risk_score,
           critical_count, high_count, medium_count, low_count, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now().isoformat(),
            len(audits),
            round(avg_risk, 1),
            sum(1 for a in audits if a.risk_level == "Critical"),
            sum(1 for a in audits if a.risk_level == "High"),
            sum(1 for a in audits if a.risk_level == "Medium"),
            sum(1 for a in audits if a.risk_level == "Low"),
            notes,
        )
    )
    run_id = cursor.lastrowid

    for audit in audits:
        cursor = conn.execute(
            """INSERT INTO machine_audits
               (run_id, hostname, folder_name, ip_address, os_name, risk_score, risk_level,
                critical_findings, high_findings, medium_findings, low_findings, total_findings,
                bitlocker_enabled, defender_running, edr_detected, edr_name,
                patch_gap_days, last_patch_date, collection_time, analyzed_at, full_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                audit.hostname,
                audit.folder_name,
                audit.system_info.ip,
                audit.system_info.os_name,
                audit.risk_score,
                audit.risk_level,
                audit.critical_count,
                audit.high_count,
                audit.medium_count,
                audit.low_count,
                len(audit.findings),
                1 if audit.security_posture.bitlocker_enabled else 0,
                1 if audit.security_posture.defender_running else 0,
                1 if audit.security_posture.edr_detected else 0,
                audit.security_posture.edr_name,
                audit.patch_gap_days,
                audit.last_patch_date,
                audit.collection_time,
                audit.analyzed_at,
                json.dumps({
                    "system_info": {
                        "hostname": audit.system_info.hostname, "ip": audit.system_info.ip,
                        "os": audit.system_info.os_name, "model": audit.system_info.model,
                    },
                    "security_posture": {
                        "bitlocker": audit.security_posture.bitlocker_enabled,
                        "defender": audit.security_posture.defender_running,
                        "edr": audit.security_posture.edr_detected,
                    },
                }),
            )
        )
        machine_id = cursor.lastrowid

        for f in audit.findings:
            conn.execute(
                """INSERT INTO findings
                   (machine_audit_id, hostname, severity, category, title,
                    description, remediation, owner, attacker_context, is_compound)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (machine_id, audit.hostname, f.severity, f.category, f.title,
                 f.description, f.remediation, f.owner, f.attacker_context,
                 1 if f.is_compound else 0)
            )

    conn.commit()
    conn.close()
    return run_id


def get_trend_data(hostname: Optional[str] = None, db_path: str = DB_PATH) -> List[dict]:
    """Get historical risk scores for trend analysis."""
    init_db(db_path)
    conn = get_connection(db_path)

    if hostname:
        rows = conn.execute(
            """SELECT ar.run_date, ma.risk_score, ma.risk_level,
                      ma.critical_findings, ma.total_findings
               FROM machine_audits ma
               JOIN audit_runs ar ON ma.run_id = ar.id
               WHERE ma.hostname = ?
               ORDER BY ar.run_date""",
            (hostname,)
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT run_date, avg_risk_score as risk_score,
                      critical_count, total_machines
               FROM audit_runs
               ORDER BY run_date"""
        ).fetchall()

    conn.close()
    return [dict(r) for r in rows]


def get_all_runs(db_path: str = DB_PATH) -> List[dict]:
    """Get all audit run summaries."""
    init_db(db_path)
    conn = get_connection(db_path)
    rows = conn.execute(
        "SELECT * FROM audit_runs ORDER BY run_date DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
