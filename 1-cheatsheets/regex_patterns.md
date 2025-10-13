# Regex Patterns Cheat Sheet for SOC Analysts

**Purpose:** Quick reference for regular expressions used in log analysis, SIEM searches, and threat hunting in a SOC environment.

> Designed for **practical use** — all patterns are tested and ready for real-world scenarios.

---

## 1. Basic Patterns

| Pattern | Description | Example |
|---------|------------|---------|
| `.` | Any single character | `a.c` matches `abc`, `a1c` |
| `*` | Zero or more occurrences of the previous character | `ab*` matches `a`, `ab`, `abb` |
| `+` | One or more occurrences of the previous character | `ab+` matches `ab`, `abb` |
| `?` | Zero or one occurrence | `colou?r` matches `color` or `colour` |
| `\d` | Any digit | `\d{3}` matches `123`, `456` |
| `\w` | Any word character (a-z, A-Z, 0-9, _) | `\w+` matches `username_1` |
| `\s` | Any whitespace character | `\s+` matches space, tab, newline |
| `^` | Start of line | `^Failed` matches lines starting with `Failed` |
| `$` | End of line | `password$` matches lines ending with `password` |

---

## 2. Common SOC Use Cases

| Task | Regex Pattern | Notes |
|------|---------------|------|
| Extract IP addresses | `\b(?:\d{1,3}\.){3}\d{1,3}\b` | Matches IPv4 addresses |
| Extract email addresses | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}` | Detect phishing or user info |
| Extract URLs | `https?://[^\s]+` | Detect suspicious links |
| Extract failed login attempts | `Failed password for .* from (\b(?:\d{1,3}\.){3}\d{1,3}\b)` | Capture IP of failed logins |
| Extract sudo usage | `sudo:.*` | Find privilege escalation attempts |
| Extract dates (YYYY-MM-DD) | `\d{4}-\d{2}-\d{2}` | Useful for log timestamps |
| Extract time (HH:MM:SS) | `\b\d{2}:\d{2}:\d{2}\b` | Combine with date for timeline analysis |

---

## 3. Advanced Patterns for Threat Hunting

| Task | Regex Pattern | Notes |
|------|---------------|------|
| Extract log levels | `\b(INFO|WARN|ERROR|CRITICAL)\b` | Quickly filter log severity |
| Extract hash values (MD5, SHA1, SHA256) | `\b[a-fA-F0-9]{32,64}\b` | Detect malware or file indicators |
| Detect SQL injection attempts | `(union select|select \* from|--|#)` | Basic SQLi detection |
| Detect XSS attempts | `(<script>|</script>|javascript:)` | Simple cross-site scripting detection |
| Extract CIDR ranges | `\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b` | For network monitoring |

---

## 🔹 Notes for SOC Analysts
- Always test regex in your environment — field names and log formats may vary.  
- Combine with `grep -P`, Splunk `rex`, or Python `re` module for automation.  
- Keep patterns **modular**: you can reuse the same regex across multiple logs, dashboards, or scripts.  
- Start broad, refine with filtering — improves efficiency and accuracy.

---
