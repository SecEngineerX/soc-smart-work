# Splunk Queries Cheat Sheet for SOC Analysts

**Purpose:** Quick reference of essential Splunk search queries for log analysis, threat detection, and incident response in a Security Operations Center (SOC) environment.  

> Designed for **practical use** — all queries can be adapted to real-world logs and SIEM dashboards.

---

## 1. Basic Searches

| Task | Splunk Query | Notes |
|------|-------------|------|
| Search all logs | `index=main` | Start broad, narrow later |
| Search by host | `index=main host="hostname"` | Focus on specific endpoint |
| Search by source type | `index=main sourcetype="syslog"` | Filter for log type |
| Search by keyword | `index=main "Failed password"` | Useful for brute force detection |
| Time-bound search | `index=main earliest=-24h latest=now` | Last 24 hours |

---

## 2. Failed Login Detection

| Task | Splunk Query | Notes |
|------|-------------|------|
| Count failed logins | `index=auth "Failed password" | stats count by user, host` | Detect repeated failures |
| Top offending IPs | `index=auth "Failed password" | stats count by src_ip | sort -count` | Rank attackers |
| Alert for threshold | `index=auth "Failed password" | stats count by src_ip | where count>5` | Customize threshold for alerting |

---

## 3. Successful Logins & Privilege Escalation

| Task | Splunk Query | Notes |
|------|-------------|------|
| Successful logins | `index=auth "Accepted password" | stats count by user, host` | Verify authorized access |
| Sudo usage | `index=auth "sudo:" | stats count by user` | Monitor privilege escalation |
| Unusual login times | `index=auth "Accepted password" | eval hour=strftime(_time,"%H") | stats count by hour` | Detect anomalies |

---

## 4. Network & Firewall Logs

| Task | Splunk Query | Notes |
|------|-------------|------|
| Blocked connections | `index=firewall action="blocked" | stats count by src_ip, dest_ip` | Detect attempted intrusions |
| Top destination ports | `index=firewall action="allowed" | stats count by dest_port | sort -count` | Monitor traffic patterns |
| Traffic by host | `index=firewall | stats sum(bytes) by host` | Identify heavy traffic |

---

## 5. Web & Application Logs

| Task | Splunk Query | Notes |
|------|-------------|------|
| 404 errors | `index=web "404" | stats count by uri` | Detect broken pages or probing |
| SQL injection attempts | `index=web "union select" OR "select * from" | stats count by src_ip` | Basic web attack detection |
| Suspicious user agents | `index=web | stats count by user_agent` | Detect abnormal traffic |

---

## 6. Alerts & Reporting

| Task | Splunk Query | Notes |
|------|-------------|------|
| Daily summary of failed logins | `index=auth "Failed password" earliest=-1d@d latest=@d | stats count by user, host` | Ready for automated reports |
| Top 10 IPs by events | `index=* | stats count by src_ip | sort -count | head 10` | Quick overview of high-activity sources |
| Count events per host | `index=* | stats count by host` | Identify active endpoints |

---

## 🔹 Notes for SOC Analysts
- Replace `index`, `sourcetype`, and field names according to your environment.  
- Combine `eval`, `stats`, and `where` commands to create **custom detections**.  
- Use these queries to **feed dashboards, alerts, and automation scripts**.  
- Start broad, refine with filters — a good SOC workflow practice.  

---
