
"""
🌐 Network Audit Module
External exposure checks and risk classification using nmap.
"""
 
import subprocess
import re
import shutil
 
 
def run_cmd(cmd, timeout=60):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", 1
    except Exception as e:
        return f"ERROR: {e}", 1
 
 
# Port risk classification table
PORT_RISK = {
    # (description, severity, recommendation)
    20:    ("FTP Data",           "HIGH",   "Disable FTP. Use SFTP/SCP instead."),
    21:    ("FTP Control",        "HIGH",   "Disable FTP. Use SFTP/SCP instead."),
    22:    ("SSH",                "LOW",    "Ensure key-based auth is enforced."),
    23:    ("Telnet",             "HIGH",   "Disable Telnet immediately. Use SSH."),
    25:    ("SMTP",               "MEDIUM", "Restrict relay. Use TLS. Consider port 587."),
    53:    ("DNS",                "MEDIUM", "Ensure not open to the public unless intended."),
    80:    ("HTTP",               "MEDIUM", "Redirect to HTTPS. Consider closing port 80."),
    110:   ("POP3",               "MEDIUM", "Use POP3S (port 995) instead."),
    135:   ("MS RPC",             "HIGH",   "Block from external. Windows RPC exposure."),
    139:   ("NetBIOS",            "HIGH",   "Block from external. SMB/NetBIOS exposure."),
    143:   ("IMAP",               "MEDIUM", "Use IMAPS (port 993) instead."),
    443:   ("HTTPS",              "LOW",    "Verify SSL/TLS certificate is valid."),
    445:   ("SMB",                "HIGH",   "Block port 445 from public internet."),
    3306:  ("MySQL",              "HIGH",   "Bind to localhost only. Block external access."),
    3389:  ("RDP",                "HIGH",   "Restrict RDP access via VPN or IP whitelist."),
    5432:  ("PostgreSQL",         "HIGH",   "Bind to localhost. Block external access."),
    5900:  ("VNC",                "HIGH",   "Use VPN for remote access instead of VNC."),
    6379:  ("Redis",              "HIGH",   "Bind to localhost. Add authentication."),
    8080:  ("HTTP-Alt",           "MEDIUM", "Investigate purpose. Consider firewall restriction."),
    8443:  ("HTTPS-Alt",          "LOW",    "Ensure valid SSL certificate."),
    27017: ("MongoDB",            "HIGH",   "Bind to localhost. Enable authentication."),
}
 
 
class NetworkAuditor:
 
    def __init__(self, target="localhost"):
        self.target = target
 
    def run(self):
        findings = []
        findings += self.check_nmap_available()
        if self._nmap_ok:
            findings += self.scan_ports()
            findings += self.detect_services()
            findings += self.check_icmp_broadcast()
        else:
            # Fallback: use ss/netstat when nmap is not available
            findings += self.fallback_port_check()
        findings += self.check_ipv6_enabled()
        findings += self.check_ip_forwarding()
        return findings
 
    # ── Nmap Availability ──────────────────────────────────────────
    def check_nmap_available(self):
        self._nmap_ok = shutil.which("nmap") is not None
        if self._nmap_ok:
            return [{
                "module": "NETWORK",
                "check": "Nmap Availability",
                "status": "INFO",
                "severity": "LOW",
                "detail": "nmap is available — performing full port scan",
                "recommendation": "None",
            }]
        return [{
            "module": "NETWORK",
            "check": "Nmap Availability",
            "status": "WARN",
            "severity": "LOW",
            "detail": "nmap not found — using ss fallback for port checks",
            "recommendation": "Install nmap for detailed scans: sudo apt install nmap",
        }]
 
    # ── Nmap Port Scan ─────────────────────────────────────────────
    def scan_ports(self):
        findings = []
        print(f"    [nmap] SYN scan on {self.target} ...")
        output, rc = run_cmd(
            f"nmap -sS --open -p- --min-rate 500 {self.target} 2>/dev/null",
            timeout=120,
        )
        if rc != 0 or not output:
            # Fallback: -sT (connect) scan, no root required
            output, rc = run_cmd(
                f"nmap -sT --open -F {self.target} 2>/dev/null",
                timeout=60,
            )
 
        open_ports = re.findall(r"(\d+)/tcp\s+open\s+(\S+)", output)
        self._open_ports = open_ports
 
        for port_str, service in open_ports:
            port = int(port_str)
            desc, severity, rec = PORT_RISK.get(port, (
                f"Unknown service ({service})",
                "MEDIUM",
                f"Investigate port {port}. If not needed, close with: sudo ufw deny {port}",
            ))
            findings.append({
                "module": "NETWORK",
                "check": f"Port {port} open ({desc})",
                "status": "WARN",
                "severity": severity,
                "detail": f"TCP/{port} is open — {desc} ({service})",
                "recommendation": rec,
            })
 
        if not findings:
            findings.append({
                "module": "NETWORK",
                "check": "Port Scan Results",
                "status": "PASS",
                "severity": "LOW",
                "detail": "No open ports detected on target",
                "recommendation": "None",
            })
        return findings
 
    # ── Nmap Service Detection ─────────────────────────────────────
    def detect_services(self):
        findings = []
        if not hasattr(self, "_open_ports") or not self._open_ports:
            return findings
        ports_str = ",".join(p for p, _ in self._open_ports[:20])
        print(f"    [nmap] Service/version detection on open ports ...")
        output, _ = run_cmd(
            f"nmap -sV -p {ports_str} {self.target} 2>/dev/null",
            timeout=60,
        )
        # Look for outdated/vulnerable versions
        old_patterns = {
            r"OpenSSH\s+[1-6]\.":       ("Outdated OpenSSH version",       "HIGH"),
            r"Apache\s+1\.":             ("Apache 1.x — End of Life",       "HIGH"),
            r"Apache\s+2\.[0-3]\.":      ("Outdated Apache version",        "MEDIUM"),
            r"nginx\s+0\.":              ("Outdated nginx version",          "MEDIUM"),
            r"vsftpd\s+2\.[0-2]":        ("Outdated vsftpd",                "MEDIUM"),
            r"MySQL\s+5\.[0-6]":         ("Outdated MySQL — consider 8.x",  "MEDIUM"),
        }
        for pattern, (desc, severity) in old_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                findings.append({
                    "module": "NETWORK",
                    "check": f"Outdated Service Detected",
                    "status": "FAIL",
                    "severity": severity,
                    "detail": desc,
                    "recommendation": "Update the service to the latest stable version: "
                                      "sudo apt update && sudo apt upgrade",
                })
        return findings
 
    # ── ICMP Broadcast ─────────────────────────────────────────────
    def check_icmp_broadcast(self):
        output, _ = run_cmd("sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null")
        if "= 1" in output:
            return [{
                "module": "NETWORK",
                "check": "CIS 3.2.5 — ICMP Broadcast",
                "status": "PASS",
                "severity": "LOW",
                "detail": "ICMP broadcast responses are disabled",
                "recommendation": "None",
            }]
        return [{
            "module": "NETWORK",
            "check": "CIS 3.2.5 — ICMP Broadcast",
            "status": "FAIL",
            "severity": "MEDIUM",
            "detail": "System responds to ICMP broadcast (Smurf amplification risk)",
            "recommendation": "Run: echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' "
                              ">> /etc/sysctl.conf && sudo sysctl -p",
        }]
 
    # ── IPv6 Status ────────────────────────────────────────────────
    def check_ipv6_enabled(self):
        output, _ = run_cmd("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null")
        if "= 1" in output:
            return [{
                "module": "NETWORK",
                "check": "IPv6 Status",
                "status": "INFO",
                "severity": "LOW",
                "detail": "IPv6 is disabled",
                "recommendation": "Enable if IPv6 connectivity is needed.",
            }]
        return [{
            "module": "NETWORK",
            "check": "IPv6 Status",
            "status": "INFO",
            "severity": "LOW",
            "detail": "IPv6 is enabled — ensure firewall rules cover IPv6 (ip6tables/ufw)",
            "recommendation": "Verify: sudo ip6tables -L or sudo ufw status verbose",
        }]
 
    # ── IP Forwarding ──────────────────────────────────────────────
    def check_ip_forwarding(self):
        output, _ = run_cmd("sysctl net.ipv4.ip_forward 2>/dev/null")
        if "= 0" in output:
            return [{
                "module": "NETWORK",
                "check": "CIS 3.1.1 — IP Forwarding",
                "status": "PASS",
                "severity": "LOW",
                "detail": "IP forwarding is disabled",
                "recommendation": "None",
            }]
        return [{
            "module": "NETWORK",
            "check": "CIS 3.1.1 — IP Forwarding",
            "status": "WARN",
            "severity": "MEDIUM",
            "detail": "IP forwarding is ENABLED — system may be acting as a router",
            "recommendation": "Disable unless this machine is a router/gateway: "
                              "echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf && sudo sysctl -p",
        }]
 
    # ── Fallback (no nmap) ─────────────────────────────────────────
    def fallback_port_check(self):
        findings = []
        output, _ = run_cmd("ss -tuln 2>/dev/null")
        for line in output.splitlines():
            m = re.search(r":(\d+)\s", line)
            if m:
                port = int(m.group(1))
                if port in PORT_RISK:
                    desc, severity, rec = PORT_RISK[port]
                    findings.append({
                        "module": "NETWORK",
                        "check": f"Port {port} open ({desc})",
                        "status": "WARN",
                        "severity": severity,
                        "detail": f"{desc} detected on port {port}",
                        "recommendation": rec,
                    })
        if not findings:
            findings.append({
                "module": "NETWORK",
                "check": "Fallback Port Scan (ss)",
                "status": "PASS",
                "severity": "LOW",
                "detail": "No high-risk ports detected via ss",
                "recommendation": "Install nmap for a more thorough scan",
            })
        return findings
