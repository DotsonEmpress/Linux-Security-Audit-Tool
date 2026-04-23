#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   Unified Security, Compliance & Network Audit Tool  ║
║   Ubuntu Edition                                     ║
╚══════════════════════════════════════════════════════╝
 
Usage:
    sudo python3 audit.py                  # Full audit
    sudo python3 audit.py --security       # Security only
    sudo python3 audit.py --compliance     # Compliance only
    sudo python3 audit.py --network        # Network only
    sudo python3 audit.py --target <IP>    # Network scan on specific IP
    sudo python3 audit.py --output html    # Generate HTML report
"""
 
import argparse
import sys
import os
from datetime import datetime
 
# Module imports
from modules.security_audit import SecurityAuditor
from modules.compliance_audit import ComplianceAuditor
from modules.network_audit import NetworkAuditor
from modules.report_generator import ReportGenerator
 
 
def banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║   🔐 Unified Security, Compliance & Network Audit Tool  ║
║      Ubuntu Edition  |  CIS-Style Checks                ║
╚══════════════════════════════════════════════════════════╝
    """)
 
 
def check_root():
    if os.geteuid() != 0:
        print("[!] WARNING: Some checks require root privileges.")
        print("    Run with: sudo python3 audit.py\n")
 
 
def parse_args():
    parser = argparse.ArgumentParser(
        description="Unified Security, Compliance & Network Audit Tool for Ubuntu"
    )
    parser.add_argument("--security",   action="store_true", help="Run security audit only")
    parser.add_argument("--compliance", action="store_true", help="Run compliance checks only")
    parser.add_argument("--network",    action="store_true", help="Run network audit only")
    parser.add_argument("--target",     type=str, default="localhost",
                        help="Target IP for network scan (default: localhost)")
    parser.add_argument("--output",     choices=["text", "html"], default="text",
                        help="Report output format (default: text)")
    parser.add_argument("--save",       action="store_true",
                        help="Save report to file")
    return parser.parse_args()
 
 
def main():
    banner()
    check_root()
    args = parse_args()
 
    # Determine which modules to run
    run_all = not (args.security or args.compliance or args.network)
 
    findings = {
        "metadata": {
            "hostname": os.uname().nodename,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": args.target,
        },
        "security":   [],
        "compliance": [],
        "network":    [],
    }
 
    # ── Security Audit ────────────────────────────────────────────
    if run_all or args.security:
        print("[*] Running Security Audit...")
        auditor = SecurityAuditor()
        findings["security"] = auditor.run()
        print(f"    Done — {len(findings['security'])} checks completed.\n")
 
    # ── Compliance Audit ──────────────────────────────────────────
    if run_all or args.compliance:
        print("[*] Running Compliance Checks...")
        compliance = ComplianceAuditor()
        findings["compliance"] = compliance.run()
        print(f"    Done — {len(findings['compliance'])} checks completed.\n")
 
    # ── Network Audit ─────────────────────────────────────────────
    if run_all or args.network:
        print(f"[*] Running Network Audit on target: {args.target} ...")
        network = NetworkAuditor(target=args.target)
        findings["network"] = network.run()
        print(f"    Done — {len(findings['network'])} findings.\n")
 
    # ── Generate Report ───────────────────────────────────────────
    reporter = ReportGenerator(findings)
 
    if args.output == "html":
        report = reporter.generate_html()
        filename = f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    else:
        report = reporter.generate_text()
        filename = f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
 
    print(report)
 
    if args.save:
        with open(filename, "w") as f:
            f.write(report)
        print(f"\n[✔] Report saved to: {filename}")
 
 
if __name__ == "__main__":
    main()
