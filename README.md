# 🦉 OwlEye AI — Autonomous SOC Intelligence Platform

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

> **Built by Solomon Omakun** — Cybersecurity Engineer | SOC Automation Specialist

OwlEye AI is a fully autonomous, multi-agent Security Operations Center (SOC) intelligence platform that detects, investigates, contains, and documents security incidents — without human intervention — except for a deliberate human approval gate before containment actions are executed.

It replicates and surpasses the capabilities of a Tier 2 SOC analyst team, running 24/7 at machine speed.

---

## 🎯 What It Does

| Stage | Agent | Action |
|-------|-------|--------|
| 1 | **Monitor Agent** | Ingests Windows Event Logs, detects 13 attack categories |
| 2 | **Triage Agent** | Scores alerts 0–100, escalates high-risk incidents |
| 3 | **Investigation Agent** | MITRE ATT&CK mapping, AbuseIPDB + VirusTotal enrichment |
| 4 | **Approval Gate** | Sends Slack alert, waits for human approval |
| 5 | **Containment Agent** | Blocks IP, flags user, logs all actions |
| 6 | **Documentation Agent** | Generates 12-section PDF report, emails it automatically |
| 7 | **Flask Dashboard** | Real-time SOC view with Approve/Reject controls |

**From attack detected to contained and documented — in under 2 minutes.**

---

## 🚨 Attack Detection Coverage (13 Categories)

| Attack | MITRE Technique | Severity |
|--------|----------------|----------|
| Brute Force Login | T1110 | HIGH |
| Password Guessing | T1110.001 | HIGH |
| Credential Abuse (Valid Accounts) | T1078 | HIGH |
| Kerberos Pre-Auth Failure | T1558 | MEDIUM |
| NTLM Auth / Pass-the-Hash | T1550.002 | MEDIUM |
| New User Account Created | T1136 | HIGH |
| User Account Deleted | T1531 | HIGH |
| Privilege Escalation (Group Membership) | T1098 | CRITICAL |
| Persistence via Service | T1543 | HIGH |
| Audit Log Cleared | T1070.001 | CRITICAL |
| Scheduled Task Abuse | T1053.005 | HIGH |
| Process Injection | T1055 | CRITICAL |
| Credential Dumping Tools (Mimikatz, Cobalt Strike, etc.) | T1003 | CRITICAL |

---

## 🏗️ Architecture