"""
OwlEye AI - Human Approval Gate
Sends investigated incidents to Solomon via Slack.
Waits for APPROVE or DENY before containment executes.
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
    format="%(asctime)s [APPROVAL] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("approval_gate")

DB_PATH = Path(__file__).parent.parent / "owleye.db"
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")


def get_investigated_incidents():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id, event_type, severity, triage_score, raw_data
        FROM incidents
        WHERE status = 'investigated'
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


def send_slack_alert(incident_id, event_type, severity, triage_score, investigation):
    if not SLACK_WEBHOOK:
        log.warning("No Slack webhook configured")
        return False

    ip = investigation.get("raw", {}).get("source_ip", "N/A")
    mitre = investigation.get("mitre", {})
    ip_intel = investigation.get("ip_intel", {})
    recommendation = investigation.get("recommendation", "N/A")
    auto_blocked = investigation.get("auto_blocked", False)

    blocked_text = "YES - Already auto-blocked" if auto_blocked else "NO - Awaiting your approval"

    message = {
        "text": f":rotating_light: *OwlEye AI — Threat Detected* :rotating_light:",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "OwlEye AI - Incident Alert"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident ID:*\n#{incident_id}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Event:*\n{event_type}"},
                    {"type": "mrkdwn", "text": f"*Triage Score:*\n{triage_score}/100"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n{ip}"},
                    {"type": "mrkdwn", "text": f"*IP Malicious:*\n{ip_intel.get('abuse_confidence', 'N/A')}%"},
                    {"type": "mrkdwn", "text": f"*Country:*\n{ip_intel.get('country', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Tor Exit Node:*\n{ip_intel.get('is_tor', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*MITRE Technique:*\n{mitre.get('technique_id')} - {mitre.get('technique_name')}"},
                    {"type": "mrkdwn", "text": f"*Tactic:*\n{mitre.get('tactic')}"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommendation:*\n{recommendation}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*IP Auto-Blocked:* {blocked_text}"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*ACTION REQUIRED:* Reply with:\n`APPROVE {incident_id}` to proceed with containment\n`DENY {incident_id}` to hold and monitor"
                }
            }
        ]
    }

    try:
        r = requests.post(SLACK_WEBHOOK, json=message, timeout=10)
        if r.status_code == 200:
            log.info("Slack alert sent for Incident #%d", incident_id)
            return True
        else:
            log.error("Slack error: %s", r.text)
    except Exception as e:
        log.error("Slack send failed: %s", e)
    return False


def run(interval_seconds=20):
    log.info("=" * 60)
    log.info("  OwlEye AI - Human Approval Gate Starting")
    log.info("  Slack webhook: %s", "configured" if SLACK_WEBHOOK else "NOT configured")
    log.info("=" * 60)

    notified = set()

    while True:
        incidents = get_investigated_incidents()

        if not incidents:
            log.info("No incidents awaiting approval...")
        else:
            for row in incidents:
                incident_id, event_type, severity, triage_score, raw_data_str = row
                if incident_id in notified:
                    continue

                investigation = json.loads(raw_data_str)
                log.info("Sending approval request for Incident #%d", incident_id)

                sent = send_slack_alert(
                    incident_id, event_type, severity, triage_score, investigation
                )

                if sent:
                    update_incident_status(incident_id, "pending_approval")
                    notified.add(incident_id)
                    log.info("Incident #%d status -> pending_approval", incident_id)

        time.sleep(interval_seconds)


if __name__ == "__main__":
    run(interval_seconds=20)