"""
OwlEye AI — Monitor Agent
Runs continuously, ingests Windows Event Logs and simulated log entries,
detects anomalies, and raises alerts for the Triage Agent.
"""

import os
import json
import time
import sqlite3
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env", override=True)

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MONITOR] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("monitor_agent")

# ── Database setup ─────────────────────────────────────────────────────────────
DB_PATH = Path(__file__).parent.parent / "owleye.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            raw_data TEXT NOT NULL,
            status TEXT DEFAULT 'new',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            added_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()
    log.info("Database initialized at %s", DB_PATH)

def save_alert(source: str, event_type: str, severity: str, raw_data: dict):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO alerts (timestamp, source, event_type, severity, raw_data)
        VALUES (?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat(),
        source,
        event_type,
        severity,
        json.dumps(raw_data)
    ))
    conn.commit()
    alert_id = c.lastrowid
    conn.close()
    log.info("Alert saved [ID:%d] | %s | %s | %s", alert_id, severity.upper(), event_type, source)
    return alert_id

# ── Detection rules ────────────────────────────────────────────────────────────
SUSPICIOUS_EVENT_IDS = {
    4625: ("Failed Login Attempt", "medium"),
    4648: ("Explicit Credential Login", "medium"),
    4720: ("New User Account Created", "high"),
    4726: ("User Account Deleted", "high"),
    4728: ("User Added to Privileged Group", "critical"),
    4732: ("User Added to Local Admin Group", "critical"),
    4756: ("User Added to Universal Group", "high"),
    4771: ("Kerberos Pre-Auth Failed", "medium"),
    4776: ("NTLM Auth Attempt", "low"),
    7045: ("New Service Installed", "high"),
    4688: ("New Process Created", "low"),
    1102: ("Audit Log Cleared", "critical"),
    4698: ("Scheduled Task Created", "high"),
}

SUSPICIOUS_PROCESSES = [
    "mimikatz", "pwdump", "procdump", "meterpreter",
    "cobalt", "empire", "psexec", "wce.exe", "fgdump"
]

def parse_windows_events():
    alerts = []
    try:
        ps_cmd = (
            "Get-WinEvent -LogName Security -MaxEvents 50 | "
            "Select-Object Id, TimeCreated, Message | "
            "ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0 or not result.stdout.strip():
            return alerts

        events = json.loads(result.stdout)
        if isinstance(events, dict):
            events = [events]

        for event in events:
            event_id = event.get("Id")
            if event_id in SUSPICIOUS_EVENT_IDS:
                event_type, severity = SUSPICIOUS_EVENT_IDS[event_id]
                alert_data = {
                    "event_id": event_id,
                    "time": event.get("TimeCreated", ""),
                    "message": event.get("Message", "")[:500],
                    "source": "Windows Security Log"
                }
                alerts.append((
                    "Windows Event Log",
                    f"EventID {event_id}: {event_type}",
                    severity,
                    alert_data
                ))
    except subprocess.TimeoutExpired:
        log.warning("PowerShell event query timed out")
    except json.JSONDecodeError:
        log.warning("Could not parse Windows event log output")
    except Exception as e:
        log.error("Windows event log error: %s", e)
    return alerts


def check_suspicious_processes():
    alerts = []
    try:
        result = subprocess.run(
            ["powershell", "-Command", "Get-Process | Select-Object Name, Id | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return alerts

        processes = json.loads(result.stdout)
        if isinstance(processes, dict):
            processes = [processes]

        for proc in processes:
            name = proc.get("Name", "").lower()
            for suspicious in SUSPICIOUS_PROCESSES:
                if suspicious in name:
                    alerts.append((
                        "Process Monitor",
                        f"Suspicious Process Detected: {proc['Name']}",
                        "critical",
                        {"process_name": proc["Name"], "pid": proc.get("Id"), "matched": suspicious}
                    ))
    except Exception as e:
        log.error("Process check error: %s", e)
    return alerts


def simulate_sample_alert():
    return (
        "Simulated Log Source",
        "Brute Force Login Attempt",
        "high",
        {
            "event_id": 4625,
            "source_ip": "185.220.101.45",
            "target_user": "Administrator",
            "attempt_count": 47,
            "time": datetime.utcnow().isoformat(),
            "message": "Multiple failed login attempts detected from single IP"
        }
    )


def run(interval_seconds: int = 60, simulate: bool = False):
    log.info("=" * 60)
    log.info("  OwlEye AI — Monitor Agent Starting")
    log.info("  Polling interval: %ds", interval_seconds)
    log.info("  Simulation mode: %s", simulate)
    log.info("=" * 60)

    init_db()

    cycle = 0
    while True:
        cycle += 1
        log.info("── Scan cycle #%d ──────────────────────────────────", cycle)

        all_alerts = []

        if simulate:
            if cycle % 3 == 0:
                all_alerts.append(simulate_sample_alert())
                log.info("Simulation: generated test alert")
            else:
                log.info("Simulation: no events this cycle")
        else:
            win_alerts = parse_windows_events()
            proc_alerts = check_suspicious_processes()
            all_alerts = win_alerts + proc_alerts
            log.info("Found %d suspicious event(s) this cycle", len(all_alerts))

        for source, event_type, severity, raw_data in all_alerts:
            save_alert(source, event_type, severity, raw_data)

        log.info("Sleeping %ds until next scan...", interval_seconds)
        time.sleep(interval_seconds)


if __name__ == "__main__":
    run(interval_seconds=30, simulate=True)