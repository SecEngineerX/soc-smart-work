# SOC-Smart-Work 🛡️

**Practical SOC Analyst Portfolio** — a curated collection of scripts, dashboards, playbooks, labs, and cheat sheets designed to demonstrate real-world cybersecurity skills.  

This repo showcases **automation, threat hunting, incident response, and hands-on SOC workflow** in a professional and recruiter-friendly format.

---

## 🔹 Table of Contents

1. [Cheat Sheets](#-cheat-sheets)  
2. [Automation Scripts](#-automation-scripts)  
3. [Dashboards](#-dashboards)  
4. [Playbooks](#-playbooks)  
5. [Labs](#-labs)  
6. [Documentation](#-documentation)  
7. [Getting Started](#-getting-started)  
8. [License](#-license)

---

## 💡 Cheat Sheets
Quick reference guides to accelerate SOC work:

- **Linux Commands** → essential terminal commands for investigation  
- **Splunk Queries** → reusable queries for log analysis  
- **Regex Patterns** → commonly used patterns for searching and parsing logs  

*Location:* `1-cheatsheets/`

---

## 🖥️ Automation Scripts
Practical scripts to **work smart, not hard**:

- **log_parser.py** → parses logs, detects failed logins & HTTP errors, outputs JSON  
- **bulk_hash_lookup.py** → queries file hashes against threat intelligence  
- **phishing_url_checker.py** → scans URLs for phishing indicators  

*Location:* `2-automation-scripts/`

---

## 📊 Dashboards
Visual SOC intelligence at a glance:

- **SIEM Dashboard Design** → recommended layouts for monitoring key events  
- **Threat Hunting Dashboard** → sample screenshots of actionable insights  
- **MITRE ATT&CK Mapping** → mapping threats to MITRE techniques  

*Location:* `3-dashboards/`

---

## 📖 Playbooks
Step-by-step SOC response guides:

- **Incident Response: Phishing**  
- **Malware Investigation**  
- **Privilege Escalation Detection**  

*Location:* `4-playbooks/`

---

## 🧪 Labs
Hands-on exercises demonstrating practical SOC skills:

- **Brute Force Detection** → parse logs and detect suspicious login patterns  
- **Phishing Analysis** → analyze malicious emails with scripts and lab reports  
- **Malware Triage** → sample analysis and YARA rules  

*Location:* `5-labs/`

---

## 📂 Documentation
Professional diagrams and project overview:

- **SOC Workflow Diagram** → `docs/soc_workflow.png`  
- **Incident Flowchart** → `docs/incident_flowchart.drawio`  
- **Project Overview** → `docs/project_overview.md`  

---

## 🚀 Getting Started

1. Clone the repo:

```bash
git clone https://github.com/SecEngineerX/soc-smart-work.git
cd soc-smart-work
