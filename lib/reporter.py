"""Report generation module"""

import json
from pathlib import Path
from datetime import datetime

class ReportGenerator:
    """Generate TXT and JSON reports from findings"""

    def __init__(self, results_dir, target):
        self.results_dir = Path(results_dir)
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_txt_report(self, findings):
        """Generate human-readable TXT report"""
        output_file = self.results_dir / f"bbrecon_report_{self.timestamp}.txt"

        with open(output_file, "w") as f:
            f.write("="*80 + "\n")
            f.write(f"BBHUNT SECURITY REPORT\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")

            # Metadata
            f.write("SCAN SUMMARY\n")
            f.write("-"*80 + "\n")
            meta = findings.get("scan_metadata", {})
            for key, value in meta.items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            f.write("\n")

            # Subdomains
            subdomains = findings.get("subdomains", [])
            if subdomains:
                f.write(f"SUBDOMAINS ({len(subdomains)})\n")
                f.write("-"*80 + "\n")
                for sub in subdomains:
                    f.write(f"{sub.get('subdomain', '')}\n")
                f.write("\n")

            # Live Hosts
            live_hosts = findings.get("live_hosts", [])
            if live_hosts:
                f.write(f"LIVE HOSTS ({len(live_hosts)})\n")
                f.write("-"*80 + "\n")
                for host in live_hosts:
                    status = host.get('status_code', 'N/A')
                    if status and status != '404':
                        f.write(f"URL: {host.get('url', '')}\n")
                        f.write(f"  Status: {status}\n")
                        if host.get('title'):
                            f.write(f"  Title: {host['title']}\n")
                        if host.get('technologies'):
                            f.write(f"  Tech: {host['technologies']}\n")
                        f.write("\n")

            # Bruteforced Subdomains
            bruteforced = findings.get("bruteforced_subdomains", [])
            if bruteforced:
                f.write(f"BRUTEFORCED SUBDOMAINS ({len(bruteforced)})\n")
                f.write("-"*80 + "\n")
                for sub in bruteforced:
                    f.write(f"{sub.get('subdomain', '')}\n")
                f.write("\n")

            # Vulnerabilities
            vulns = findings.get("vulnerabilities", [])
            if vulns:
                f.write(f"VULNERABILITIES ({len(vulns)})\n")
                f.write("-"*80 + "\n")
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        if 'raw' in vuln:
                            f.write(f"{vuln['raw']}\n\n")
                        else:
                            f.write(f"[{vuln.get('severity', 'UNKNOWN').upper()}] {vuln.get('name', 'Unknown')}\n")
                            f.write(f"  Template: {vuln.get('template', 'N/A')}\n")
                            f.write(f"  URL: {vuln.get('url', 'N/A')}\n")
                            if vuln.get('description'):
                                f.write(f"  Description: {vuln['description']}\n")
                            f.write("\n")

            # XSS Findings
            xss = findings.get("xss_findings", [])
            if xss:
                f.write(f"XSS FINDINGS ({len(xss)})\n")
                f.write("-"*80 + "\n")
                for finding in xss:
                    f.write(f"URL: {finding.get('url', '')}\n")
                    f.write(f"  Evidence: {finding.get('evidence', '')}\n\n")

            # Directory Findings
            dirs = findings.get("directory_findings", [])
            if dirs:
                f.write(f"DIRECTORY FINDINGS ({len(dirs)})\n")
                f.write("-"*80 + "\n")
                for d in dirs:
                    if 'url' in d:
                        f.write(f"[{d.get('status', 'N/A')}] {d.get('url', '')} ({d.get('length', 0)} bytes)\n")
                    else:
                        f.write(f"{d.get('raw', '')}\n")
                f.write("\n")

            # URLs
            urls = findings.get("urls", [])
            if urls:
                f.write(f"COLLECTED URLS ({len(urls)})\n")
                f.write("-"*80 + "\n")
                for url_item in urls[:500]:  # Limit to 500 URLs
                    f.write(f"{url_item.get('url', '')}\n")
                if len(urls) > 500:
                    f.write(f"\n... and {len(urls) - 500} more URLs\n")
                f.write("\n")

            f.write("="*80 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*80 + "\n")

        return output_file

    def generate_json_report(self, findings):
        """Generate structured JSON report"""
        output_file = self.results_dir / f"bbrecon_report_{self.timestamp}.json"

        # Add metadata
        report = {
            "scan_date": datetime.now().isoformat(),
            "target": self.target,
            "tool": "BBHUNT v2.0.0",
            "findings": findings,
        }

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, sort_keys=True)

        return output_file
