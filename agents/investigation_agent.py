"""
OwlEye AI - Investigation Agent
Takes escalated incidents, enriches IPs via AbuseIPDB and VirusTotal,
maps techniques to MITRE ATT&CK, and builds a full incident brief.
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
    format="%(asctime)s [INVESTIGATION] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("investigation_agent")

DB_PATH = Path(__file__).parent.parent / "owleye.db"

MITRE_MAP = {
    "Brute Force Login Attempt": ("T1110", "Brute Force", "Credential Access"),
    "Failed Login Attempt": ("T1110.001", "Password Guessing", "Credential Access"),
    "Explicit Credential Login": ("T1078", "Valid Accounts", "Defense Evasion"),
    "New User Account Created": ("T1136", "Create Account", "Persistence"),
    "User Account Deleted": ("T1531", "Account Access Removal", "Impact"),
    "User Added to Privileged Group": ("T1098", "Account Manipulation", "Persistence"),
    "User Added to Local Admin Group": ("T1098", "Account Manipulation", "Persistence"),
    "New Service Installed": ("T1543", "Create or Modify System Process", "Persistence"),
    "Audit Log Cleared": ("T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
    "Scheduled Task Created": ("T1053.005", "Scheduled Task", "Persistence"),
    "Suspicious Process Detected": ("T1055", "Process Injection", "Defense Evasion"),
}


def get_open_incidents():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id, alert_id, event_type, severity, triage_score, raw_data
        FROM incidents
        WHERE status = 'open'
        ORDER BY created_at ASC
    """)
    rows = c.fetchall()
    conn.close()
    return rows


def update_incident(incident_id, status, investigation):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE incidents SET status = ?, raw_data = ? WHERE id = ?",
        (status, json.dumps(investigation), incident_id)
    )
    conn.commit()
    conn.close()


def add_to_blocklist(ip, reason):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT OR IGNORE INTO blocklist (ip_address, reason) VALUES (?, ?)",
        (ip, reason)
    )
    conn.commit()
    conn.close()
    log.info("  BLOCKED: %s - %s", ip, reason)


def check_abuseipdb(ip):
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key or not ip:
        return {}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "ip": ip,
                "abuse_confidence": d.get("abuseConfidenceScore", 0),
                "country": d.get("countryCode", "Unknown"),
                "isp": d.get("isp", "Unknown"),
                "total_reports": d.get("totalReports", 0),
                "is_tor": d.get("isTor", False),
            }
    except Exception as e:
        log.error("AbuseIPDB error: %s", e)
    return {}


def check_virustotal_ip(ip):
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key or not ip:
        return {}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=10
        )
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "vendors_flagged": stats.get("malicious", 0) + stats.get("suspicious", 0),
            }
    except Exception as e:
        log.error("VirusTotal error: %s", e)
    return {}


def map_mitre(event_type):
    for key, (tid, tname, tactic) in MITRE_MAP.items():
        if key.lower() in event_type.lower():
            return {
                "technique_id": tid,
                "technique_name": tname,
                "tactic": tactic,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            }
    return {"technique_id": "Unknown", "technique_name": "Unknown", "tactic": "Unknown"}


def investigate(incident_id, alert_id, event_type, severity, triage_score, raw_data_str):
    raw_data = json.loads(raw_data_str)
    log.info("-- Investigating Incident #%d | %s", incident_id, event_type)

    result = {
        "incident_id": incident_id,
        "alert_id": alert_id,
        "event_type": event_type,
        "severity": severity,
        "triage_score": triage_score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw": raw_data,
        "mitre": {},
        "ip_intel": {},
        "vt_intel": {},
        "auto_blocked": False,
        "recommendation": "",
    }

    mitre = map_mitre(event_type)
    result["mitre"] = mitre
    log.info("  MITRE: %s - %s (%s)", mitre["technique_id"], mitre["technique_name"], mitre["tactic"])

    src_ip = raw_data.get("source_ip", "")
    if src_ip:
        abuse = check_abuseipdb(src_ip)
        if abuse:
            result["ip_intel"] = abuse
            confidence = abuse.get("abuse_confidence", 0)
            log.info("  AbuseIPDB: %d%% malicious | %s | Tor: %s",
                     confidence, abuse.get("country"), abuse.get("is_tor"))
            if confidence >= 80:
                add_to_blocklist(src_ip, f"AbuseIPDB {confidence}% confidence")
                result["auto_blocked"] = True

        vt = check_virustotal_ip(src_ip)
        if vt:
            result["vt_intel"] = vt
            log.info("  VirusTotal: %d vendors flagged", vt.get("vendors_flagged", 0))

    if triage_score >= 90:
        rec = "IMMEDIATE ACTION - Contain and isolate. Awaiting human approval."
    elif triage_score >= 70:
        rec = "HIGH PRIORITY - Investigate lateral movement. Monitor affected accounts."
    elif triage_score >= 50:
        rec = "MODERATE - Watch for persistence. Check related events."
    else:
        rec = "LOW - Log and monitor."

    result["recommendation"] = rec
    log.info("  Recommendation: %s", rec)

    update_incident(incident_id, "investigated", result)
    log.info("  Incident #%d investigation complete", incident_id)
    return result


def run(interval_seconds=15):
    log.info("=" * 60)
    log.info("  OwlEye AI - Investigation Agent Starting")
    log.info("  Polling interval: %ds", interval_seconds)
    log.info("=" * 60)

    while True:
        incidents = get_open_incidents()
        if not incidents:
            log.info("No open incidents. Watching...")
        else:
            log.info("Found %d open incident(s)", len(incidents))
            for row in incidents:
                investigate(*row)
        time.sleep(interval_seconds)


if __name__ == "__main__":
    run(interval_seconds=15)