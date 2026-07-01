"""
OwlEye AI - Containment Agent
Executes containment actions on approved incidents.
Blocks IPs, logs actions, and updates incident status.
"""

import os
import json
import time
import sqlite3
import logging
import requests
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env", override=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CONTAINMENT] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("containment_agent")

DB_PATH = Path(__file__).parent.parent / "owleye.db"
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")


def get_approved_incidents():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id, event_type, severity, triage_score, raw_data
        FROM incidents
        WHERE status = 'approved'
        ORDER BY created_at ASC
    """)
    rows = c.fetchall()
    conn.close()
    return rows


def update_incident_status(incident_id, status):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE incidents SET status = ? WHERE id = ?",
        (status, incident_id)
    )
    conn.commit()
    conn.close()


def block_ip(ip, reason):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT OR IGNORE INTO blocklist (ip_address, reason) VALUES (?, ?)",
        (ip, reason)
    )
    conn.commit()
    conn.close()
    log.info("  IP BLOCKED: %s — %s", ip, reason)


def log_containment_action(incident_id, action, details):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS containment_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            action TEXT,
            details TEXT,
            executed_at TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute(
        "INSERT INTO containment_log (incident_id, action, details) VALUES (?, ?, ?)",
        (incident_id, action, json.dumps(details))
    )
    conn.commit()
    conn.close()


def send_slack_confirmation(incident_id, actions_taken):
    if not SLACK_WEBHOOK:
        return
    message = {
        "text": f":white_check_mark: *OwlEye AI — Containment Executed*",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Containment Complete"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Incident #{incident_id}* has been contained.\n\n*Actions Taken:*\n" +
                            "\n".join(f"• {a}" for a in actions_taken)
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"_Executed at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC_"
                }
            }
        ]
    }
    try:
        requests.post(SLACK_WEBHOOK, json=message, timeout=10)
        log.info("  Slack confirmation sent")
    except Exception as e:
        log.error("  Slack error: %s", e)


def contain(incident_id, event_type, severity, triage_score, raw_data_str):
    raw_data = json.loads(raw_data_str)
    investigation = raw_data if "mitre" in raw_data else {}
    actual_raw = investigation.get("raw", raw_data)

    log.info("== Executing Containment for Incident #%d ==", incident_id)
    actions_taken = []

    # 1. Block source IP
    src_ip = actual_raw.get("source_ip", "")
    if src_ip:
        block_ip(src_ip, f"Containment — Incident #{incident_id} | {event_type}")
        actions_taken.append(f"IP blocked: {src_ip}")
        log_containment_action(incident_id, "IP_BLOCK", {"ip": src_ip})

    # 2. Log targeted user if present
    target_user = actual_raw.get("target_user", "")
    if target_user:
        log.info("  TARGET USER: %s — flag for password reset", target_user)
        actions_taken.append(f"User flagged for review: {target_user}")
        log_containment_action(incident_id, "USER_FLAG", {"user": target_user})

    # 3. Log event type containment
    log.info("  EVENT: %s contained", event_type)
    actions_taken.append(f"Event type contained: {event_type}")
    log_containment_action(incident_id, "EVENT_CONTAIN", {
        "event_type": event_type,
        "severity": severity,
        "score": triage_score
    })

    # 4. Update status
    update_incident_status(incident_id, "contained")
    log.info("  Incident #%d status -> contained", incident_id)

    # 5. Send Slack confirmation
    send_slack_confirmation(incident_id, actions_taken)

    log.info("== Containment Complete for Incident #%d ==", incident_id)
    return actions_taken


def run(interval_seconds=15):
    log.info("=" * 60)
    log.info("  OwlEye AI - Containment Agent Starting")
    log.info("  Waiting for approved incidents...")
    log.info("=" * 60)

    while True:
        incidents = get_approved_incidents()

        if not incidents:
            log.info("No approved incidents. Watching...")
        else:
            log.info("Found %d approved incident(s) — executing containment", len(incidents))
            for row in incidents:
                contain(*row)

        time.sleep(interval_seconds)


if __name__ == "__main__":
    run(interval_seconds=15)