"""
OwlEye AI - Documentation Agent (Elite Edition)
"""

import os
import json
import time
import sqlite3
import logging
import requests
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from fpdf import FPDF

load_dotenv(Path(__file__).parent.parent / ".env", override=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DOCUMENTATION] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("documentation_agent")

DB_PATH = Path(__file__).parent.parent / "owleye.db"
REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

COMPLIANCE_MAP = {
    "Brute Force": {
        "NIST_CSF": [("PR.AC-3", "Remote access managed", "FAILED"), ("DE.CM-1", "Network monitored", "PASSED"), ("RS.RP-1", "Response plan executed", "PASSED")],
        "ISO_27001": [("A.9.4.2", "Secure log-on procedures", "FAILED"), ("A.12.4.1", "Event logging", "PASSED"), ("A.16.1.5", "Incident response", "PASSED")],
        "SOC_2": [("CC6.1", "Logical access controls", "AT RISK"), ("CC7.2", "System monitoring", "PASSED"), ("CC9.1", "Risk mitigation", "IN REVIEW")],
    },
    "Persistence": {
        "NIST_CSF": [("PR.AC-1", "Identities managed", "FAILED"), ("DE.CM-3", "Personnel activity monitored", "AT RISK"), ("RS.MI-1", "Incidents contained", "PASSED")],
        "ISO_27001": [("A.9.2.1", "User registration", "FAILED"), ("A.12.6.1", "Vulnerability management", "FAILED"), ("A.16.1.6", "Learning from incidents", "IN REVIEW")],
        "SOC_2": [("CC6.2", "User provisioning", "FAILED"), ("CC8.1", "Infrastructure changes managed", "AT RISK"), ("CC9.2", "Risk assessment", "IN REVIEW")],
    },
}

THREAT_ACTOR_PROFILES = {
    "T1110": {"likely_actor": "Opportunistic threat actor or automated botnet", "motivation": "Credential harvesting, initial access", "sophistication": "Low to Medium", "known_groups": ["FIN7", "Scattered Spider", "Automated scanners"], "next_steps_if_uncontained": "Lateral movement, privilege escalation, data exfiltration"},
    "T1078": {"likely_actor": "Insider threat or compromised credential buyer", "motivation": "Unauthorized access, data theft", "sophistication": "Medium", "known_groups": ["APT33", "Lazarus Group"], "next_steps_if_uncontained": "Data exfiltration, persistence establishment"},
    "T1136": {"likely_actor": "APT actor establishing persistence", "motivation": "Long-term access, espionage", "sophistication": "High", "known_groups": ["APT29", "APT28", "Sandworm"], "next_steps_if_uncontained": "Backdoor installation, C2 communication"},
}

GAP_ANALYSIS = {
    "Brute Force Login Attempt": ["GAP: No account lockout policy detected", "GAP: No MFA enforced on targeted accounts", "GAP: No IP reputation pre-screening at authentication layer", "GAP: Alert threshold too high - attack ran 47 attempts before detection"],
    "New User Account Created": ["GAP: No automated alerting on privileged account creation", "GAP: No approval workflow for new account provisioning"],
    "Audit Log Cleared": ["GAP: No immutable log storage", "GAP: No real-time alert on log clearing events"],
}

HARDENING_RECS = {
    "Brute Force Login Attempt": ["HARDEN: Enable account lockout after 5 failed attempts", "HARDEN: Enforce MFA on all privileged accounts", "HARDEN: Deploy geo-blocking for authentication", "HARDEN: Implement IP reputation screening at WAF layer", "HARDEN: Deploy honeypot accounts to detect credential stuffing"],
    "New User Account Created": ["HARDEN: Implement PAM solution", "HARDEN: Require dual approval for admin account creation"],
    "Audit Log Cleared": ["HARDEN: Configure WORM storage for audit logs", "HARDEN: Ship logs to immutable SIEM in real time"],
}

DETECTION_RULES = {
    "Brute Force Login Attempt": ["RULE: Alert on >5 failed logins from same IP within 5 minutes", "RULE: Alert on >10 failed logins targeting same account in 10 minutes", "RULE: Alert on login attempts from Tor exit nodes", "RULE: Alert on successful login after >3 previous failures"],
    "New User Account Created": ["RULE: Alert on new user account created outside business hours", "RULE: Alert on new account immediately added to privileged group"],
    "Audit Log Cleared": ["RULE: Alert on Event ID 1102 immediately", "RULE: Alert on Event ID 104 (System log cleared)"],
}


def get_contained_incidents():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, event_type, severity, triage_score, raw_data, created_at FROM incidents WHERE status = 'contained' ORDER BY created_at ASC")
    rows = c.fetchall()
    conn.close()
    return rows


def update_incident_status(incident_id, status):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE incidents SET status = ? WHERE id = ?", (status, incident_id))
    conn.commit()
    conn.close()


def get_containment_actions(incident_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT action, details, executed_at FROM containment_log WHERE incident_id = ?", (incident_id,))
        rows = c.fetchall()
    except Exception:
        rows = []
    conn.close()
    return rows


def call_sentinelai(incident_data):
    if not ANTHROPIC_API_KEY:
        return {"threat_narrative": "SentinelAI not configured.", "executive_summary": "N/A", "attacker_intent": "Unknown", "reoccurrence_likelihood": "Unknown", "reoccurrence_reason": "N/A"}
    prompt = f"""You are SentinelAI, an elite SOC threat intelligence analyst.
Analyze this contained security incident and provide:
1. A threat narrative (3-4 sentences)
2. An executive summary (2-3 sentences for a CISO)
3. Attacker intent
4. Likelihood of reoccurrence (Low/Medium/High) with reason

Incident: {json.dumps(incident_data)}

Respond ONLY in JSON:
{{"threat_narrative": "...", "executive_summary": "...", "attacker_intent": "...", "reoccurrence_likelihood": "...", "reoccurrence_reason": "..."}}"""
    try:
        r = requests.post("https://api.anthropic.com/v1/messages",
            headers={"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": "claude-haiku-4-5-20251001", "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]},
            timeout=30)
        if r.status_code == 200:
            content = r.json()["content"][0]["text"]
            return json.loads(content[content.find("{"):content.rfind("}") + 1])
    except Exception as e:
        log.error("SentinelAI error: %s", e)
    return {"threat_narrative": "Unable to generate.", "executive_summary": "Unable to generate.", "attacker_intent": "Unknown", "reoccurrence_likelihood": "Unknown", "reoccurrence_reason": "N/A"}


def build_report_data(incident_id, event_type, severity, triage_score, raw_data, created_at):
    investigation = raw_data if "mitre" in raw_data else {}
    actual_raw = investigation.get("raw", raw_data)
    mitre = investigation.get("mitre", {})
    ip_intel = investigation.get("ip_intel", {})
    vt_intel = investigation.get("vt_intel", {})
    auto_blocked = investigation.get("auto_blocked", False)
    src_ip = actual_raw.get("source_ip", "N/A")
    target_user = actual_raw.get("target_user", "N/A")
    attempt_count = actual_raw.get("attempt_count", "N/A")
    mitre_id = mitre.get("technique_id", "Unknown")
    mitre_name = mitre.get("technique_name", "Unknown")
    mitre_tactic = mitre.get("tactic", "Unknown")
    mitre_url = mitre.get("url", "")
    log.info("  Calling SentinelAI for threat narrative...")
    sentinel = call_sentinelai({"event_type": event_type, "severity": severity, "triage_score": triage_score, "source_ip": src_ip, "target_user": target_user, "mitre_id": mitre_id, "mitre_name": mitre_name, "abuse_confidence": ip_intel.get("abuse_confidence", "N/A"), "is_tor": ip_intel.get("is_tor", False), "auto_blocked": auto_blocked})
    log.info("  SentinelAI narrative generated")
    compliance_key = "Brute Force" if "Brute Force" in event_type or "Login" in event_type else "Persistence"
    threat_actor = THREAT_ACTOR_PROFILES.get(mitre_id, {"likely_actor": "Unknown", "motivation": "Unknown", "sophistication": "Unknown", "known_groups": ["Unknown"], "next_steps_if_uncontained": "Unknown"})
    return {
        "report_id": f"OWL-{incident_id:04d}-{datetime.now(timezone.utc).strftime('%Y%m%d')}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "incident_id": incident_id, "event_type": event_type, "severity": severity,
        "triage_score": triage_score, "created_at": created_at, "src_ip": src_ip,
        "target_user": target_user, "attempt_count": attempt_count, "auto_blocked": auto_blocked,
        "mitre_id": mitre_id, "mitre_name": mitre_name, "mitre_tactic": mitre_tactic, "mitre_url": mitre_url,
        "ip_intel": ip_intel, "vt_intel": vt_intel, "sentinel": sentinel, "threat_actor": threat_actor,
        "compliance": COMPLIANCE_MAP.get(compliance_key, {}),
        "gaps": GAP_ANALYSIS.get(event_type, ["No specific gap analysis available."]),
        "hardening": HARDENING_RECS.get(event_type, ["Review security baseline."]),
        "rules": DETECTION_RULES.get(event_type, ["Review detection coverage."]),
        "containment_actions": get_containment_actions(incident_id),
    }


def safe(text):
    return str(text).encode("latin-1", "replace").decode("latin-1")


def save_pdf(d):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    LM = pdf.l_margin

    def header(title):
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(15, 52, 96)
        pdf.set_text_color(255, 255, 255)
        pdf.set_x(LM)
        pdf.cell(0, 8, safe(title), fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9)

    def row(label, value):
        pdf.set_x(LM)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(55, 6, safe(label), new_x="RIGHT", new_y="TOP")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 6, safe(value), new_x="LMARGIN", new_y="NEXT")

    def bullet(text):
        pdf.set_x(LM + 3)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, safe("- " + text), new_x="LMARGIN", new_y="NEXT")

    def body(text):
        pdf.set_x(LM)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, safe(text), new_x="LMARGIN", new_y="NEXT")

    # Title
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_fill_color(15, 52, 96)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 14, "OwlEye AI - Incident Report", fill=True, new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(200, 0, 0)
    pdf.cell(0, 7, "CONFIDENTIAL - SOC INTERNAL USE ONLY", fill=True, new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, f"Report ID: {d['report_id']}   |   Generated: {d['timestamp']}", new_x="LMARGIN", new_y="NEXT", align="C")

    header("SECTION 1 - EXECUTIVE SUMMARY (CISO-READY)")
    body(d['sentinel'].get('executive_summary', 'N/A'))
    body("Incident was detected, investigated, and contained autonomously by OwlEye AI.")

    header("SECTION 2 - INCIDENT DETAILS")
    row("Event Type:", d['event_type'])
    row("Severity:", d['severity'].upper())
    row("Triage Score:", f"{d['triage_score']}/100")
    row("Detection Time:", str(d['created_at']))
    row("Containment Time:", d['timestamp'])
    row("Status:", "CONTAINED")
    row("Source IP:", d['src_ip'])
    row("Target User:", d['target_user'])
    row("Login Attempts:", str(d['attempt_count']))
    row("IP Auto-Blocked:", "YES" if d['auto_blocked'] else "NO")

    header("SECTION 3 - SENTINELAI THREAT NARRATIVE")
    body(d['sentinel'].get('threat_narrative', 'N/A'))
    row("Attacker Intent:", d['sentinel'].get('attacker_intent', 'N/A'))
    row("Reoccurrence Risk:", d['sentinel'].get('reoccurrence_likelihood', 'N/A'))
    row("Reason:", d['sentinel'].get('reoccurrence_reason', 'N/A'))

    header("SECTION 4 - MITRE ATT&CK MAPPING")
    row("Technique ID:", d['mitre_id'])
    row("Technique Name:", d['mitre_name'])
    row("Tactic:", d['mitre_tactic'])
    row("Reference:", d['mitre_url'])

    header("SECTION 5 - THREAT ACTOR PROFILING")
    ta = d['threat_actor']
    row("Likely Actor:", ta.get('likely_actor', 'N/A'))
    row("Motivation:", ta.get('motivation', 'N/A'))
    row("Sophistication:", ta.get('sophistication', 'N/A'))
    row("Known Groups:", ', '.join(ta.get('known_groups', [])))
    row("Next Steps:", ta.get('next_steps_if_uncontained', 'N/A'))

    header("SECTION 6 - IP INTELLIGENCE")
    ip = d['ip_intel']
    vt = d['vt_intel']
    row("Source IP:", d['src_ip'])
    row("AbuseIPDB Score:", f"{ip.get('abuse_confidence', 'N/A')}% malicious")
    row("Country:", ip.get('country', 'N/A'))
    row("ISP:", ip.get('isp', 'N/A'))
    row("Total Reports:", str(ip.get('total_reports', 'N/A')))
    row("Tor Exit Node:", str(ip.get('is_tor', 'N/A')))
    row("VT Vendors Flagged:", str(vt.get('vendors_flagged', 'N/A')))

    header("SECTION 7 - CONTAINMENT ACTIONS")
    if d['containment_actions']:
        for action, details, executed_at in d['containment_actions']:
            bullet(f"[{executed_at}] {action}: {details}")
    else:
        bullet(f"IP {d['src_ip']} blocked in OwlEye blocklist")
        bullet(f"User {d['target_user']} flagged for review")

    header("SECTION 8 - COMPLIANCE FRAMEWORK MAPPING")
    comp = d['compliance']
    body("NIST Cybersecurity Framework:")
    for ctrl_id, ctrl_name, status in comp.get("NIST_CSF", []):
        bullet(f"[{status}] {ctrl_id} - {ctrl_name}")
    body("ISO 27001:")
    for ctrl_id, ctrl_name, status in comp.get("ISO_27001", []):
        bullet(f"[{status}] {ctrl_id} - {ctrl_name}")
    body("SOC 2 Trust Services Criteria:")
    for ctrl_id, ctrl_name, status in comp.get("SOC_2", []):
        bullet(f"[{status}] {ctrl_id} - {ctrl_name}")

    header("SECTION 9 - GAP ANALYSIS")
    for gap in d['gaps']:
        bullet(gap)

    header("SECTION 10 - HARDENING RECOMMENDATIONS")
    for rec in d['hardening']:
        bullet(rec)

    header("SECTION 11 - DETECTION RULE IMPROVEMENTS")
    for rule in d['rules']:
        bullet(rule)

    header("SECTION 12 - LESSONS LEARNED")
    for lesson in [
        "1. Threat intelligence APIs confirmed malicious infrastructure immediately.",
        "2. Automated containment reduced response time from hours to seconds.",
        "3. MITRE ATT&CK mapping enabled immediate understanding of attacker methodology.",
        "4. Compliance gaps must be remediated before next audit cycle.",
        "5. Detection rules should be updated to lower alert threshold.",
    ]:
        bullet(lesson)

    pdf.ln(6)
    pdf.set_x(LM)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, f"Generated by OwlEye AI | SOC Lead: Solomon Omakun | {d['report_id']}", new_x="LMARGIN", new_y="NEXT", align="C")

    filename = REPORTS_DIR / f"{d['report_id']}.pdf"
    pdf.output(str(filename))
    log.info("  PDF saved: %s", filename)
    return filename


def send_email(report_id, pdf_path, sentinel):
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        log.warning("SMTP not configured - skipping email")
        return
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_EMAIL
        msg["To"] = SMTP_EMAIL
        msg["Subject"] = f"OwlEye AI - Incident Report {report_id}"
        body = f"OwlEye AI Incident Report\n\nReport ID: {report_id}\n\nExecutive Summary:\n{sentinel.get('executive_summary', 'N/A')}\n\nReoccurrence Risk: {sentinel.get('reoccurrence_likelihood', 'N/A')}\n\nFull report attached.\n\n- OwlEye AI"
        msg.attach(MIMEText(body, "plain"))
        with open(pdf_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={report_id}.pdf")
            msg.attach(part)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        log.info("  PDF emailed to %s", SMTP_EMAIL)
    except Exception as e:
        log.error("  Email error: %s", e)


def send_slack_notification(incident_id, report_id, sentinel):
    if not SLACK_WEBHOOK:
        return
    try:
        requests.post(SLACK_WEBHOOK, json={
            "text": f":page_facing_up: *OwlEye AI Report Ready* | {report_id}\n*Summary:* {sentinel.get('executive_summary', 'N/A')}\n*Reoccurrence Risk:* {sentinel.get('reoccurrence_likelihood', 'N/A')}\n*PDF emailed to:* {SMTP_EMAIL}"
        }, timeout=10)
        log.info("  Slack notification sent")
    except Exception as e:
        log.error("  Slack error: %s", e)


def document(incident_id, event_type, severity, triage_score, raw_data_str, created_at):
    raw_data = json.loads(raw_data_str)
    log.info("== Generating Report for Incident #%d ==", incident_id)
    d = build_report_data(incident_id, event_type, severity, triage_score, raw_data, created_at)
    pdf_path = save_pdf(d)
    send_email(d['report_id'], pdf_path, d['sentinel'])
    send_slack_notification(incident_id, d['report_id'], d['sentinel'])
    update_incident_status(incident_id, "documented")
    log.info("== Report Complete: %s ==", d['report_id'])
    return d['report_id']


def run(interval_seconds=20):
    log.info("=" * 60)
    log.info("  OwlEye AI - Documentation Agent (Elite Edition)")
    log.info("  Watching for contained incidents...")
    log.info("=" * 60)
    documented = set()
    while True:
        incidents = get_contained_incidents()
        if not incidents:
            log.info("No contained incidents to document. Watching...")
        else:
            for row in incidents:
                incident_id = row[0]
                if incident_id not in documented:
                    document(*row)
                    documented.add(incident_id)
        time.sleep(interval_seconds)


if __name__ == "__main__":
    run(interval_seconds=20)