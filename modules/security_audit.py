
"""
🔐 Security Audit Module
Checks local machine vulnerabilities and security posture.
"""
 
import subprocess
import stat
import os
import re
 
 
def run_cmd(cmd):
    """Run a shell command and return stdout."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"
 
 
class SecurityAuditor:
 
    def run(self):
        findings = []
        findings += self.check_open_ports()
        findings += self.check_firewall()
        findings += self.check_suid_sgid()
        findings += self.check_sensitive_file_permissions()
        findings += self.check_running_services()
        findings += self.check_world_writable_dirs()
        findings += self.check_empty_passwords()
        return findings
 
    # ── 1. Open Ports ──────────────────────────────────────────────
    def check_open_ports(self):
        findings = []
        output = run_cmd("ss -tuln 2>/dev/null")
        risky_ports = {
            21:   ("FTP – transmits in plain text",         "HIGH"),
            23:   ("Telnet – transmits in plain text",      "HIGH"),
            25:   ("SMTP – verify if intentional",          "MEDIUM"),
            80:   ("HTTP – unencrypted web traffic",        "MEDIUM"),
            443:  ("HTTPS – standard secure web",           "LOW"),
            3306: ("MySQL – should not be public-facing",   "HIGH"),
            5432: ("PostgreSQL – should not be public",     "HIGH"),
            6379: ("Redis – often left unauthenticated",    "HIGH"),
            8080: ("HTTP Alternate – verify if needed",     "MEDIUM"),
        }
        for line in output.splitlines():
            for port, (desc, severity) in risky_ports.items():
                if f":{port} " in line or f":{port}\t" in line:
                    findings.append({
                        "module": "SECURITY",
                        "check": f"Open Port {port}",
                        "status": "WARN",
                        "severity": severity,
                        "detail": desc,
                        "recommendation": f"Confirm port {port} is necessary. "
                                          f"If not, close with: sudo ufw deny {port}",
                    })
        if not findings:
            findings.append({
                "module": "SECURITY",
                "check": "Open Ports Scan",
                "status": "PASS",
                "severity": "LOW",
                "detail": "No high-risk ports detected",
                "recommendation": "None",
            })
        return findings
 
    # ── 2. Firewall Status ─────────────────────────────────────────
    def check_firewall(self):
        output = run_cmd("ufw status 2>/dev/null")
        if "Status: active" in output:
            return [{
                "module": "SECURITY",
                "check": "Firewall (UFW)",
                "status": "PASS",
                "severity": "LOW",
                "detail": "UFW firewall is active",
                "recommendation": "None",
            }]
        return [{
            "module": "SECURITY",
            "check": "Firewall (UFW)",
            "status": "FAIL",
            "severity": "HIGH",
            "detail": "UFW firewall is NOT active",
            "recommendation": "Enable firewall: sudo ufw enable",
        }]
 
    # ── 3. SUID / SGID Files ───────────────────────────────────────
    def check_suid_sgid(self):
        findings = []
        output = run_cmd(
            "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null"
        )
        known_safe = {
            "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
            "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chfn",
            "/usr/bin/chsh", "/usr/bin/mount", "/usr/bin/umount",
            "/usr/sbin/pppd", "/bin/ping", "/bin/mount", "/bin/su",
        }
        suspicious = []
        for path in output.splitlines():
            if path and path not in known_safe:
                suspicious.append(path)
 
        if suspicious:
            findings.append({
                "module": "SECURITY",
                "check": "SUID/SGID Files",
                "status": "WARN",
                "severity": "MEDIUM",
                "detail": f"Unexpected SUID/SGID binaries found: {', '.join(suspicious[:5])}",
                "recommendation": "Review these files. Remove SUID bit if not required: "
                                  "sudo chmod -s <file>",
            })
        else:
            findings.append({
                "module": "SECURITY",
                "check": "SUID/SGID Files",
                "status": "PASS",
                "severity": "LOW",
                "detail": "No unexpected SUID/SGID files detected",
                "recommendation": "None",
            })
        return findings
 
    # ── 4. Sensitive File Permissions ──────────────────────────────
    def check_sensitive_file_permissions(self):
        findings = []
        checks = {
            "/etc/passwd": {
                "expected_mode": 0o644,
                "desc": "World-readable user database",
                "rec": "sudo chmod 644 /etc/passwd",
            },
            "/etc/shadow": {
                "expected_mode": 0o640,
                "desc": "Hashed passwords file — must be restricted",
                "rec": "sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow",
            },
            "/etc/sudoers": {
                "expected_mode": 0o440,
                "desc": "Sudoers configuration",
                "rec": "sudo chmod 440 /etc/sudoers",
            },
            "/etc/ssh/sshd_config": {
                "expected_mode": 0o600,
                "desc": "SSH daemon configuration",
                "rec": "sudo chmod 600 /etc/ssh/sshd_config",
            },
        }
        for filepath, meta in checks.items():
            if not os.path.exists(filepath):
                continue
            actual = stat.S_IMODE(os.stat(filepath).st_mode)
            if actual > meta["expected_mode"]:
                findings.append({
                    "module": "SECURITY",
                    "check": f"File Permissions: {filepath}",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": f"Too permissive ({oct(actual)}) — expected {oct(meta['expected_mode'])}. {meta['desc']}",
                    "recommendation": meta["rec"],
                })
            else:
                findings.append({
                    "module": "SECURITY",
                    "check": f"File Permissions: {filepath}",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": f"Permissions OK ({oct(actual)})",
                    "recommendation": "None",
                })
        return findings
 
    # ── 5. Running Services ────────────────────────────────────────
    def check_running_services(self):
        findings = []
        output = run_cmd("systemctl list-units --type=service --state=running --no-pager 2>/dev/null")
        risky = ["telnet", "rsh", "rlogin", "finger", "tftp", "ftp", "rexec"]
        for service in risky:
            if service in output.lower():
                findings.append({
                    "module": "SECURITY",
                    "check": f"Insecure Service: {service}",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": f"Legacy/insecure service '{service}' is running",
                    "recommendation": f"Disable immediately: sudo systemctl disable --now {service}",
                })
        if not any(f["status"] == "FAIL" for f in findings):
            findings.append({
                "module": "SECURITY",
                "check": "Running Services (insecure)",
                "status": "PASS",
                "severity": "LOW",
                "detail": "No known insecure legacy services detected",
                "recommendation": "None",
            })
        return findings
 
    # ── 6. World-Writable Directories ─────────────────────────────
    def check_world_writable_dirs(self):
        output = run_cmd(
            "find /etc /bin /sbin /usr -xdev -type d -perm -0002 2>/dev/null"
        )
        dirs = [d for d in output.splitlines() if d]
        if dirs:
            return [{
                "module": "SECURITY",
                "check": "World-Writable Directories",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"World-writable system directories found: {', '.join(dirs[:3])}",
                "recommendation": "Remove world-write bit: sudo chmod o-w <directory>",
            }]
        return [{
            "module": "SECURITY",
            "check": "World-Writable Directories",
            "status": "PASS",
            "severity": "LOW",
            "detail": "No world-writable system directories detected",
            "recommendation": "None",
        }]
 
    # ── 7. Accounts with Empty Passwords ──────────────────────────
    def check_empty_passwords(self):
        try:
            with open("/etc/shadow") as f:
                empty = [
                    line.split(":")[0]
                    for line in f
                    if len(line.split(":")) > 1 and line.split(":")[1] in ("", "!")
                ]
            if empty:
                return [{
                    "module": "SECURITY",
                    "check": "Empty/Locked Passwords",
                    "status": "WARN",
                    "severity": "MEDIUM",
                    "detail": f"Accounts with empty/locked passwords: {', '.join(empty[:5])}",
                    "recommendation": "Set strong passwords or lock accounts: sudo passwd -l <user>",
                }]
        except PermissionError:
            return [{
                "module": "SECURITY",
                "check": "Empty/Locked Passwords",
                "status": "SKIP",
                "severity": "LOW",
                "detail": "Cannot read /etc/shadow — run as root",
                "recommendation": "Re-run with sudo",
            }]
        return [{
            "module": "SECURITY",
            "check": "Empty/Locked Passwords",
            "status": "PASS",
            "severity": "LOW",
            "detail": "No accounts with empty passwords found",
            "recommendation": "None",
        }]
