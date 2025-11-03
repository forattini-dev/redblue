#!/usr/bin/env python3
"""
RedBlue Advanced Reconnaissance Script
Comprehensive OSINT and security analysis with HTML report generation
"""

import subprocess
import json
import os
from datetime import datetime
from pathlib import Path

# Configuration
DOMAIN = "tetis.io"
URL = f"https://www.{DOMAIN}"
RB_BINARY = "./target/release/redblue"

class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class ReconScanner:
    def __init__(self, domain, url, output_dir=None):
        self.domain = domain
        self.url = url
        self.output_dir = output_dir or f"recon-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.results = {}
        self.rb = RB_BINARY

        # Create output directory
        Path(self.output_dir).mkdir(exist_ok=True)

    def print_banner(self):
        """Print ASCII banner"""
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("╔════════════════════════════════════════════════════════════════╗")
        print("║          RedBlue Advanced Reconnaissance Scanner              ║")
        print("║             Comprehensive Security Analysis                    ║")
        print("╚════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.END}")
        print(f"{Colors.BLUE}Target:{Colors.END} {self.domain}")
        print(f"{Colors.BLUE}URL:{Colors.END} {self.url}")
        print(f"{Colors.BLUE}Output:{Colors.END} {self.output_dir}\n")

    def run_command(self, name, cmd, description=""):
        """Run a RedBlue command and capture output"""
        print(f"{Colors.YELLOW}▸{Colors.END} {Colors.BOLD}{description or name}{Colors.END}")

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Save output
            output_file = f"{self.output_dir}/{name}.txt"
            with open(output_file, 'w') as f:
                f.write(f"Command: {cmd}\n")
                f.write(f"Timestamp: {datetime.now()}\n")
                f.write(f"Exit Code: {result.returncode}\n")
                f.write("─" * 60 + "\n\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n\nSTDERR:\n")
                    f.write(result.stderr)

            # Store in results
            self.results[name] = {
                'description': description or name,
                'command': cmd,
                'output': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode,
                'timestamp': datetime.now().isoformat(),
                'file': output_file
            }

            if result.returncode == 0:
                print(f"  {Colors.GREEN}✓{Colors.END} Success - {len(result.stdout)} bytes\n")
            else:
                print(f"  {Colors.RED}✗{Colors.END} Failed (exit code: {result.returncode})\n")

            return result.returncode == 0

        except subprocess.TimeoutExpired:
            print(f"  {Colors.RED}✗{Colors.END} Timeout (60s exceeded)\n")
            return False
        except Exception as e:
            print(f"  {Colors.RED}✗{Colors.END} Error: {e}\n")
            return False

    def scan_domain_info(self):
        """Phase 1: Domain Information"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}[Phase 1/8] Domain Information{Colors.END}")
        print("─" * 64)

        self.run_command(
            "01-whois",
            f"{self.rb} recon domain whois {self.domain}",
            "WHOIS Lookup"
        )

    def scan_dns(self):
        """Phase 2: DNS Reconnaissance"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}[Phase 2/8] DNS Reconnaissance{Colors.END}")
        print("─" * 64)

        record_types = [
            ('A', 'IPv4 addresses'),
            ('AAAA', 'IPv6 addresses'),
            ('MX', 'Mail servers'),
            ('NS', 'Name servers'),
            ('TXT', 'Text records'),
        ]

        for i, (rtype, desc) in enumerate(record_types, 2):
            self.run_command(
                f"0{i}-dns-{rtype.lower()}",
                f"{self.rb} dns record lookup {self.domain} --type {rtype}",
                f"DNS {rtype} Records - {desc}"
            )

        # CNAME for www
        self.run_command(
            f"0{len(record_types)+2}-dns-cname-www",
            f"{self.rb} dns record lookup www.{self.domain} --type CNAME",
            "DNS CNAME for www subdomain"
        )

    def scan_subdomains(self):
        """Phase 3: Subdomain Enumeration"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}[Phase 3/8] Subdomain Enumeration{Colors.END}")
        print("─" * 64)

        self.run_command(
            "08-subdomains",
            f"{self.rb} recon domain subdomains {self.domain}",
            "Passive subdomain enumeration (CT logs)"
        )

    def scan_network(self):
        """Phase 4: Network Analysis"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}[Phase 4/8] Network Analysis{Colors.END}")
        print("─" * 64)

        # Resolve domain to IP
        try:
            result = subprocess.run(
                f"dig +short {self.domain} | head -1",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            ip = result.stdout.strip()

            if ip:
                print(f"{Colors.BLUE}Resolved IP:{Colors.END} {ip}\n")

                # Port scans
                self.run_command(
                    "09-ports-common",
                    f"{self.rb} network ports scan {ip} --preset common --timeout 3000",
                    f"Port scan - common ports on {ip}"
                )

                self.run_command(
                    "10-ports-web",
                    f"{self.rb} network ports scan {ip} --preset web --timeout 2000",
                    f"Port scan - web ports on {ip}"
                )

                # Traceroute
                self.run_command(
                    "11-traceroute",
                    f"{self.rb} network trace run {ip}",
                    f"Network path trace to {ip}"
                )
            else:
                print(f"{Colors.RED}Could not resolve {self.domain}{Colors.END}\n")

        except Exception as e:
            print(f"{Colors.RED}DNS resolution failed: {e}{Colors.END}\n")

    def scan_web_security(self):
        """Phase 5: Web Security Analysis"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}[Phase 5/8] Web Security Analysis{Colors.END}")
        print("─" * 64)

        self.run_command(
            "12-web-get",
            f"{self.rb} web asset get {self.url}",
            "HTTP GET request"
        )

        self.run_command(
            "13-web-headers",
            f"{self.rb} web asset headers {self.url}",
            "HTTP headers analysis"
        )

        self.run_command(
            "14-web-security",
            f"{self.rb} web asset security {self.url}",
            "Security headers audit"
        )

    def scan_tls(self):
        """Phase 6: TLS/SSL Analysis"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}[Phase 6/8] TLS/SSL Analysis{Colors.END}")
        print("─" * 64)

        self.run_command(
            "15-tls-cert",
            f"{self.rb} web asset cert {self.domain}",
            "TLS certificate inspection"
        )

        self.run_command(
            "16-tls-audit",
            f"{self.rb} web asset tls-audit {self.url}",
            "TLS security audit"
        )

    def scan_fingerprinting(self):
        """Phase 7: Web Technology Detection"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}[Phase 7/8] Technology Fingerprinting{Colors.END}")
        print("─" * 64)

        self.run_command(
            "17-fingerprint",
            f"{self.rb} web asset fingerprint {self.url}",
            "Web technology detection"
        )

        self.run_command(
            "18-wpscan",
            f"{self.rb} web asset wpscan {self.url}",
            "WordPress security scan"
        )

    def scan_osint(self):
        """Phase 8: OSINT & Intelligence"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}[Phase 8/8] OSINT & Vulnerability Scanning{Colors.END}")
        print("─" * 64)

        self.run_command(
            "19-harvest",
            f"{self.rb} recon domain harvest {self.domain}",
            "OSINT data harvesting"
        )

        self.run_command(
            "20-vuln-scan",
            f"{self.rb} web asset scan {self.url}",
            "Vulnerability scanning"
        )

    def generate_html_report(self):
        """Generate comprehensive HTML report"""
        print(f"\n{Colors.YELLOW}▸{Colors.END} {Colors.BOLD}Generating HTML Report{Colors.END}")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedBlue Recon Report - {self.domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e27;
            color: #e0e0e0;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            color: #00ff9f;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
        }}
        .subtitle {{
            text-align: center;
            color: #888;
            margin-bottom: 40px;
        }}
        .summary {{
            background: #1a1f3a;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            border-left: 4px solid #00ff9f;
        }}
        .summary h2 {{ color: #00ff9f; margin-bottom: 15px; }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .summary-item {{
            background: #0a0e27;
            padding: 15px;
            border-radius: 5px;
        }}
        .summary-item .label {{
            color: #888;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        .summary-item .value {{
            color: #00ff9f;
            font-size: 1.5em;
            font-weight: bold;
        }}
        .phase {{
            background: #1a1f3a;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 25px;
        }}
        .phase h2 {{
            color: #00d4ff;
            margin-bottom: 20px;
            border-bottom: 2px solid #00d4ff;
            padding-bottom: 10px;
        }}
        .scan-item {{
            background: #0a0e27;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
            border-left: 3px solid #888;
        }}
        .scan-item.success {{ border-left-color: #00ff9f; }}
        .scan-item.failed {{ border-left-color: #ff4444; }}
        .scan-item h3 {{
            color: #fff;
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        .scan-item .meta {{
            color: #888;
            font-size: 0.85em;
            margin-bottom: 10px;
        }}
        .scan-item pre {{
            background: #000;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9em;
            line-height: 1.5;
            color: #0f0;
            max-height: 400px;
            overflow-y: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            margin-right: 5px;
        }}
        .badge.success {{ background: #00ff9f; color: #000; }}
        .badge.failed {{ background: #ff4444; color: #fff; }}
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #333;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔴🔵 RedBlue Reconnaissance Report</h1>
        <div class="subtitle">
            Target: <strong>{self.domain}</strong> |
            Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>

        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="label">Total Scans</div>
                    <div class="value">{len(self.results)}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Successful</div>
                    <div class="value">{sum(1 for r in self.results.values() if r['exit_code'] == 0)}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Failed</div>
                    <div class="value">{sum(1 for r in self.results.values() if r['exit_code'] != 0)}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Target Domain</div>
                    <div class="value" style="font-size: 1.2em;">{self.domain}</div>
                </div>
            </div>
        </div>
"""

        # Group results by phase
        phases = {
            'Domain Information': [k for k in self.results.keys() if k.startswith('01')],
            'DNS Reconnaissance': [k for k in self.results.keys() if k.startswith('02') or k.startswith('03') or k.startswith('04') or k.startswith('05') or k.startswith('06') or k.startswith('07')],
            'Subdomain Enumeration': [k for k in self.results.keys() if k.startswith('08')],
            'Network Analysis': [k for k in self.results.keys() if k.startswith('09') or k.startswith('10') or k.startswith('11')],
            'Web Security': [k for k in self.results.keys() if k.startswith('12') or k.startswith('13') or k.startswith('14')],
            'TLS/SSL Analysis': [k for k in self.results.keys() if k.startswith('15') or k.startswith('16')],
            'Technology Fingerprinting': [k for k in self.results.keys() if k.startswith('17') or k.startswith('18')],
            'OSINT & Vulnerabilities': [k for k in self.results.keys() if k.startswith('19') or k.startswith('20')],
        }

        for phase_name, scan_keys in phases.items():
            if not scan_keys:
                continue

            html += f"""
        <div class="phase">
            <h2>{phase_name}</h2>
"""
            for key in sorted(scan_keys):
                scan = self.results[key]
                status_class = "success" if scan['exit_code'] == 0 else "failed"
                status_badge = "SUCCESS" if scan['exit_code'] == 0 else "FAILED"

                html += f"""
            <div class="scan-item {status_class}">
                <h3>
                    <span class="badge {status_class}">{status_badge}</span>
                    {scan['description']}
                </h3>
                <div class="meta">
                    Command: <code>{scan['command']}</code><br>
                    Time: {scan['timestamp']}
                </div>
                <pre>{scan['output'][:5000]}</pre>
            </div>
"""
            html += "        </div>\n"

        html += f"""
        <div class="footer">
            Generated by RedBlue Security Toolkit<br>
            <a href="https://github.com/yourusername/redblue" style="color: #00ff9f;">github.com/redblue</a>
        </div>
    </div>
</body>
</html>
"""

        report_file = f"{self.output_dir}/00-REPORT.html"
        with open(report_file, 'w') as f:
            f.write(html)

        print(f"  {Colors.GREEN}✓{Colors.END} HTML report generated: {report_file}\n")
        return report_file

    def run_full_scan(self):
        """Execute full reconnaissance workflow"""
        self.print_banner()

        # Run all scan phases
        self.scan_domain_info()
        self.scan_dns()
        self.scan_subdomains()
        self.scan_network()
        self.scan_web_security()
        self.scan_tls()
        self.scan_fingerprinting()
        self.scan_osint()

        # Generate report
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 64}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}✓ Reconnaissance Complete!{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 64}{Colors.END}\n")

        report_file = self.generate_html_report()

        # Print summary
        print(f"{Colors.YELLOW}Summary:{Colors.END}")
        print(f"  • Total scans: {len(self.results)}")
        print(f"  • Successful: {sum(1 for r in self.results.values() if r['exit_code'] == 0)}")
        print(f"  • Failed: {sum(1 for r in self.results.values() if r['exit_code'] != 0)}")
        print(f"  • Output directory: {self.output_dir}")
        print(f"  • HTML report: {report_file}")
        print(f"\n{Colors.GREEN}Open the report in your browser:{Colors.END}")
        print(f"  firefox {report_file}")
        print()

def main():
    scanner = ReconScanner(DOMAIN, URL)
    scanner.run_full_scan()

if __name__ == "__main__":
    main()
