# Linux Commands Cheat Sheet for SOC Analysts

**Purpose:** Quick reference of essential Linux commands for log analysis, system investigation, and threat hunting in Security Operations Center (SOC) environments.  

> This cheat sheet is designed for **practical use**, not theory. All commands are safe for analysis in isolated environments.

---

## 1. System Information

| Task | Command | Notes |
|------|---------|------|
| Show current user | `whoami` | Identify current user |
| Check system uptime | `uptime` | Useful for incident timeline analysis |
| List processes | `ps aux` | Shows all running processes |
| Real-time process monitoring | `top` / `htop` | `htop` is interactive (install if available) |
| Disk usage | `df -h` | Human-readable sizes |
| Directory sizes | `du -sh <directory>` | Quickly see folder sizes |

---

## 2. File & Directory Operations

| Task | Command | Notes |
|------|---------|------|
| List files | `ls -lah` | Long format, hidden files included |
| Change directory | `cd /path/to/dir` | Navigation |
| Create file | `touch filename` | |
| View file contents | `cat filename` | |
| View first lines | `head -n 20 filename` | Useful for log previews |
| View last lines | `tail -n 50 filename` | Live log monitoring |
| Search text in file | `grep "pattern" filename` | Case-sensitive by default |
| Recursive search | `grep -Ri "pattern" /path` | Search all subdirectories |
| Count occurrences | `grep -c "pattern" filename` | Quick metric |

---

## 3. Log Analysis

| Task | Command | Notes |
|------|---------|------|
| Monitor log in real-time | `tail -f /var/log/auth.log` | Replace with target log file |
| Filter failed logins | `grep "Failed password" /var/log/auth.log` | Detect brute force attempts |
| Extract IP addresses | `grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' /var/log/auth.log` | Quickly find source IPs |
| Count unique IPs | `grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr` | Rank by frequency |
| Find sudo attempts | `grep "sudo:" /var/log/auth.log` | Review privilege escalation attempts |

---

## 4. Network & Connectivity

| Task | Command | Notes |
|------|---------|------|
| Show network interfaces | `ip a` | Modern replacement for `ifconfig` |
| Check open ports | `ss -tuln` | TCP/UDP listening ports |
| Ping host | `ping <host>` | |
| Trace route | `traceroute <host>` | Analyze path to target |
| Check active connections | `netstat -antp` | Show established connections |

---

## 5. Package & Process Management

| Task | Command | Notes |
|------|---------|------|
| Install package | `sudo apt install <package>` | Debian/Ubuntu |
| Remove package | `sudo apt remove <package>` | |
| Check running services | `systemctl status <service>` | |
| Start/Stop service | `sudo systemctl start|stop <service>` | |

---

## 6. Permissions & Ownership

| Task | Command | Notes |
|------|---------|------|
| Show file permissions | `ls -l` | |
| Change permissions | `chmod 644 filename` | Read/write for owner, read for others |
| Change owner | `chown user:group filename` | |

---

## 🔹 Notes for SOC Analysts
- Always work on **isolated or test systems** when analyzing logs or experimenting with commands.  
- Combine commands with `grep`, `awk`, and `sort` to extract actionable intelligence quickly.  
- Use this sheet as a **foundation for automation scripts and dashboards** later.  

---
