"""
OwlEye AI — Triage Agent
Reads new alerts from the database, deduplicates, scores severity,
filters noise, and escalates genuine threats.
"""

import json
import time
import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env", override=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [TRIAGE] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("triage_agent")

DB_PATH = Path(__file__).parent.parent / "owleye.db"

# ── Severity scoring ───────────────────────────────────────────────────────────
SEVERITY_SCORE = {
    "low":      10,
    "medium":   40,
    "high":     70,
    "critical": 95,
}

# ── Noise filter — auto-close these unless repeated ───────────────────────────
AUTO_CLOSE_TYPES = [
    "NTLM Auth Attempt",
    "New Process Created",
]

def get_new_alerts():
    """Fetch all alerts with status 'new' from the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id, timestamp, source, event_type, severity, raw_data
        FROM alerts
        WHERE status = 'new'
        ORDER BY created_at ASC
    """)
    rows = c.fetchall()
    conn.close()
    return rows

def count_recent_duplicates(event_type: str, minutes: int = 10) -> int:
    """Count how many times this event_type fired in the last N minutes."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE event_type = ?
        AND created_at >= datetime('now', ?)
    """, (event_type, f"-{minutes} minutes"))
    count = c.fetchone()[0]
    conn.close()
    return count

def update_alert_status(alert_id: int, status: str, score: int = 0):
    """Update alert status: triaged, escalated, or closed."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        UPDATE alerts
        SET status = ?, raw_data = json_patch(raw_data, ?)
        WHERE id = ?
    """, (status, json.dumps({"triage_score": score}), alert_id))
    conn.commit()
    conn.close()

def save_incident(alert_id: int, event_type: str, severity: str,
                  score: int, raw_data: dict):
    """Promote a triaged alert to a full incident for investigation."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Create incidents table if it doesn't exist
    c.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            event_type TEXT,
            severity TEXT,
            triage_score INTEGER,
            raw_data TEXT,
            status TEXT DEFAULT 'open',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("""
        INSERT INTO incidents (alert_id, event_type, severity, triage_score, raw_data)
        VALUES (?, ?, ?, ?, ?)
    """, (alert_id, event_type, severity, score, json.dumps(raw_data)))
    conn.commit()
    incident_id = c.lastrowid
    conn.close()
    return incident_id

# ── Core triage logic ──────────────────────────────────────────────────────────

def triage_alert(alert_id, timestamp, source, event_type, severity, raw_data_str):
    raw_data = json.loads(raw_data_str)
    base_score = SEVERITY_SCORE.get(severity.lower(), 10)

    log.info("Triaging Alert #%d | %s | %s", alert_id, severity.upper(), event_type)

    # ── Noise filter ──
    if event_type in AUTO_CLOSE_TYPES:
        duplicate_count = count_recent_duplicates(event_type)
        if duplicate_count < 5:
            update_alert_status(alert_id, "closed", score=base_score)
            log.info("  → AUTO-CLOSED (low noise event, count=%d)", duplicate_count)
            return

    # ── Boost score based on context ──
    boost = 0

    # Boost if a known malicious IP is in the raw data
    src_ip = raw_data.get("source_ip", "")
    if src_ip:
        boost += 15
        log.info("  + Source IP present: %s (+15)", src_ip)

    # Boost for high attempt counts
    attempt_count = raw_data.get("attempt_count", 0)
    if attempt_count >= 10:
        boost += 10
        log.info("  + High attempt count: %d (+10)", attempt_count)

    # Boost for repeated events
    duplicate_count = count_recent_duplicates(event_type)
    if duplicate_count >= 3:
        boost += 20
        log.info("  + Repeated event: %dx in last 10 min (+20)", duplicate_count)

    final_score = min(base_score + boost, 100)

    # ── Decision ──
    if final_score >= 50:
        incident_id = save_incident(alert_id, event_type, severity, final_score, raw_data)
        update_alert_status(alert_id, "escalated", score=final_score)
        log.info("  → ESCALATED to Incident #%d | Score: %d/100", incident_id, final_score)
    else:
        update_alert_status(alert_id, "triaged", score=final_score)
        log.info("  → TRIAGED (monitoring) | Score: %d/100", final_score)


def run(interval_seconds: int = 20):
    log.info("=" * 60)
    log.info("  OwlEye AI — Triage Agent Starting")
    log.info("  Polling interval: %ds", interval_seconds)
    log.info("=" * 60)

    while True:
        alerts = get_new_alerts()

        if not alerts:
            log.info("No new alerts. Watching...")
        else:
            log.info("Found %d new alert(s) to triage", len(alerts))
            for row in alerts:
                triage_alert(*row)

        time.sleep(interval_seconds)


if __name__ == "__main__":
    run(interval_seconds=20)