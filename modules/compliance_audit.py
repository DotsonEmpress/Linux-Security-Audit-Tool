
"""
📏 Compliance Audit Module
CIS-style policy enforcement checks for Ubuntu systems.
"""
 
import subprocess
import os
import re
 
 
def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"
 
 
class ComplianceAuditor:
 
    def run(self):
        findings = []
        findings += self.check_ssh_root_login()
        findings += self.check_ssh_password_auth()
        findings += self.check_ssh_protocol()
        findings += self.check_ssh_max_auth_tries()
        findings += self.check_password_policy()
        findings += self.check_firewall_enabled()
        findings += self.check_automatic_updates()
        findings += self.check_audit_daemon()
        findings += self.check_ntp_sync()
        findings += self.check_unused_filesystems()
        return findings
 
    # ── SSH Configuration Checks ───────────────────────────────────
    def _get_sshd_config(self):
        """Parse /etc/ssh/sshd_config into a dict."""
        config = {}
        path = "/etc/ssh/sshd_config"
        if not os.path.exists(path):
            return config
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        config[parts[0].lower()] = parts[1].strip()
        return config
 
    def check_ssh_root_login(self):
        cfg = self._get_sshd_config()
        value = cfg.get("permitrootlogin", "yes").lower()
        if value in ("no", "without-password", "prohibit-password"):
            return [{
                "module": "COMPLIANCE",
                "check": "CIS 5.2.8 — SSH PermitRootLogin",
                "status": "PASS",
                "severity": "LOW",
                "detail": f"PermitRootLogin = {value}",
                "recommendation": "None",
            }]
        return [{
            "module": "COMPLIANCE",
            "check": "CIS 5.2.8 — SSH PermitRootLogin",
            "status": "FAIL",
            "severity": "HIGH",
            "detail": f"PermitRootLogin = '{value}' — direct root SSH access is enabled",
            "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, "
                              "then: sudo systemctl restart sshd",
        }]
 
    def check_ssh_password_auth(self):
        cfg = self._get_sshd_config()
        value = cfg.get("passwordauthentication", "yes").lower()
        if value == "no":
            return [{
                "module": "COMPLIANCE",
                "check": "CIS 5.2.11 — SSH PasswordAuthentication",
                "status": "PASS",
                "severity": "LOW",
                "detail": "PasswordAuthentication = no (key-based auth enforced)",
                "recommendation": "None",
            }]
        return [{
            "module": "COMPLIANCE",
            "check": "CIS 5.2.11 — SSH PasswordAuthentication",
            "status": "FAIL",
            "severity": "HIGH",
            "detail": "PasswordAuthentication = yes — brute-force risk",
            "recommendation": "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config. "
                              "Ensure SSH keys are set up first!",
        }]
 
    def check_ssh_protocol(self):
        cfg = self._get_sshd_config()
        # SSH Protocol directive removed in OpenSSH 7.4+, only Protocol 2 is supported
        # Check if explicitly set to 1 (bad)
        value = cfg.get("protocol", "2")
        if value == "1":
            return [{
                "module": "COMPLIANCE",
                "check": "CIS 5.2.1 — SSH Protocol Version",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "SSH Protocol 1 enabled — deprecated and insecure",
                "recommendation": "Set 'Protocol 2' or remove the Protocol directive "
                                  "(modern OpenSSH defaults to Protocol 2 only)",
            }]
        return [{
            "module": "COMPLIANCE",
            "check": "CIS 5.2.1 — SSH Protocol Version",
            "status": "PASS",
            "severity": "LOW",
            "detail": "SSH Protocol 2 in use",
            "recommendation": "None",
        }]
 
    def check_ssh_max_auth_tries(self):
        cfg = self._get_sshd_config()
        value = cfg.get("maxauthtries", "6")
        try:
            if int(value) <= 4:
                return [{
                    "module": "COMPLIANCE",
                    "check": "CIS 5.2.5 — SSH MaxAuthTries",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": f"MaxAuthTries = {value}",
                    "recommendation": "None",
                }]
        except ValueError:
            pass
        return [{
            "module": "COMPLIANCE",
            "check": "CIS 5.2.5 — SSH MaxAuthTries",
            "status": "FAIL",
            "severity": "MEDIUM",
            "detail": f"MaxAuthTries = {value} — should be ≤ 4",
            "recommendation": "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config",
        }]
 
    # ── Password Policy ─────────────────────────────────────────────
    def check_password_policy(self):
        findings = []
        login_defs = "/etc/login.defs"
        if not os.path.exists(login_defs):
            return [{
                "module": "COMPLIANCE",
                "check": "CIS 5.4 — Password Policy",
                "status": "SKIP",
                "severity": "MEDIUM",
                "detail": "/etc/login.defs not found",
                "recommendation": "Ensure login.defs exists",
            }]
        config = {}
        with open(login_defs) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        config[parts[0]] = parts[1]
 
        checks = {
            "PASS_MAX_DAYS": (90,  "≤ 90", "MEDIUM"),
            "PASS_MIN_DAYS": (7,   "≥ 7",  "LOW"),
            "PASS_MIN_LEN":  (14,  "≥ 14", "HIGH"),
            "PASS_WARN_AGE": (7,   "≥ 7",  "LOW"),
        }
        for key, (threshold, label, severity) in checks.items():
            val = config.get(key)
            if val is None:
                findings.append({
                    "module": "COMPLIANCE",
                    "check": f"CIS 5.4 — {key}",
                    "status": "FAIL",
                    "severity": severity,
                    "detail": f"{key} not set in /etc/login.defs",
                    "recommendation": f"Add '{key} {threshold}' to /etc/login.defs",
                })
                continue
            try:
                num = int(val)
                if key in ("PASS_MAX_DAYS",) and num > threshold:
                    ok = False
                elif key in ("PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE") and num < threshold:
                    ok = False
                else:
                    ok = True
            except ValueError:
                ok = False
 
            findings.append({
                "module": "COMPLIANCE",
                "check": f"CIS 5.4 — {key}",
                "status": "PASS" if ok else "FAIL",
                "severity": "LOW" if ok else severity,
                "detail": f"{key} = {val} (required: {label})",
                "recommendation": "None" if ok else f"Set '{key} {threshold}' in /etc/login.defs",
            })
        return findings
 
    # ── Firewall Enabled ───────────────────────────────────────────
    def check_firewall_enabled(self):
        output = run_cmd("ufw status 2>/dev/null")
        if "Status: active" in output:
            return [{
                "module": "COMPLIANCE",
                "check": "CIS 3.6 — Firewall Active",
                "status": "PASS",
                "severity": "LOW",
                "detail": "UFW is active",
                "recommendation": "None",
            }]
        return [{
            "module": "COMPLIANCE",
            "check": "CIS 3.6 — Firewall Active",
            "status": "FAIL",
            "severity": "HIGH",
            "detail": "UFW firewall is not active",
            "recommendation": "Run: sudo ufw enable",
        }]
 
    # ── Automatic Updates ──────────────────────────────────────────
    def check_automatic_updates(self):
        output = run_cmd(
            "systemctl is-enabled unattended-upgrades 2>/dev/null || "
            "dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'"
        )
        if "enabled" in output or "ii" in output:
            return [{
                "module": "COMPLIANCE",
                "check": "CIS 1.9 — Automatic Updates",
                "status": "PASS",
                "severity": "LOW",
                "detail": "unattended-upgrades is installed/enabled",
                "recommendation": "None",
            }]
        return [{
            "module": "COMPLIANCE",
            "check": "CIS 1.9 — Automatic Updates",
            "status": "FAIL",
            "severity": "MEDIUM",
            "detail": "Automatic security updates not enabled",
            "recommendation": "Install and enable: sudo apt install unattended-upgrades && "
                              "sudo dpkg-reconfigure -plow unattended-upgrades",
        }]
 
    # ── Audit Daemon ───────────────────────────────────────────────
    def check_audit_daemon(self):
        output = run_cmd("systemctl is-active auditd 2>/dev/null")
        if output.strip() == "active":
            return [{
                "module": "COMPLIANCE",
                "check": "CIS 4.1 — Audit Daemon (auditd)",
                "status": "PASS",
                "severity": "LOW",
                "detail": "auditd is active",
                "recommendation": "None",
            }]
        return [{
            "module": "COMPLIANCE",
            "check": "CIS 4.1 — Audit Daemon (auditd)",
            "status": "FAIL",
            "severity": "MEDIUM",
            "detail": "auditd is not running — system events are not being logged",
            "recommendation": "Install and start: sudo apt install auditd && "
                              "sudo systemctl enable --now auditd",
        }]
 
    # ── NTP Time Sync ──────────────────────────────────────────────
    def check_ntp_sync(self):
        output = run_cmd("timedatectl status 2>/dev/null")
        if "synchronized: yes" in output.lower() or "ntp service: active" in output.lower():
            return [{
                "module": "COMPLIANCE",
                "check": "CIS 2.2.1 — NTP Time Sync",
                "status": "PASS",
                "severity": "LOW",
                "detail": "System time is synchronized via NTP",
                "recommendation": "None",
            }]
        return [{
            "module": "COMPLIANCE",
            "check": "CIS 2.2.1 — NTP Time Sync",
            "status": "FAIL",
            "severity": "LOW",
            "detail": "NTP synchronization is not active — log timestamps may be unreliable",
            "recommendation": "Enable: sudo systemctl enable --now systemd-timesyncd",
        }]
 
    # ── Unused Filesystem Modules ──────────────────────────────────
    def check_unused_filesystems(self):
        findings = []
        risky_fs = ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf"]
        for fs in risky_fs:
            output = run_cmd(f"modprobe -n -v {fs} 2>/dev/null")
            if "install /bin/true" not in output and "ERROR" not in output:
                findings.append({
                    "module": "COMPLIANCE",
                    "check": f"CIS 1.1 — Unused Filesystem: {fs}",
                    "status": "WARN",
                    "severity": "LOW",
                    "detail": f"Filesystem module '{fs}' is not explicitly disabled",
                    "recommendation": f"Add 'install {fs} /bin/true' to /etc/modprobe.d/cis.conf",
                })
        if not findings:
            findings.append({
                "module": "COMPLIANCE",
                "check": "CIS 1.1 — Unused Filesystems",
                "status": "PASS",
                "severity": "LOW",
                "detail": "Risky filesystem modules are disabled",
                "recommendation": "None",
            })
        return findings
