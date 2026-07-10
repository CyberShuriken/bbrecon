"""Result parsing and consolidation module"""

import json
import re
from pathlib import Path

class ResultParser:
    """Parse and consolidate results from all tools"""

    def consolidate_findings(self, subdomains, live_hosts, bruteforced, urls,
                            vulnerabilities, xss_findings, directories):
        """Merge all results into structured format"""
        findings = {
            "target": "",
            "scan_metadata": {
                "subdomains_total": len(subdomains),
                "live_hosts_total": len(live_hosts),
                "bruteforced_total": len(bruteforced),
                "urls_total": len(urls),
                "vulnerabilities_total": len(vulnerabilities),
                "xss_total": len(xss_findings),
                "directories_total": len(directories),
            },
            "subdomains": self._parse_subdomains(subdomains),
            "live_hosts": self._parse_live_hosts(live_hosts),
            "bruteforced_subdomains": self._parse_bruteforced(bruteforced),
            "urls": self._parse_urls(urls),
            "vulnerabilities": self._parse_vulnerabilities(vulnerabilities),
            "xss_findings": self._parse_xss(xss_findings),
            "directory_findings": self._parse_directories(directories),
        }
        return findings

    def _parse_subdomains(self, subdomains):
        """Parse subdomain list"""
        return [{"subdomain": sub.strip()} for sub in subdomains if sub.strip()]

    def _parse_live_hosts(self, live_hosts):
        """Parse httpx output"""
        parsed = []
        for host in live_hosts:
            if not host.strip():
                continue
            # Skip 404 status
            if "404" in host:
                continue

            parts = host.split()
            entry = {
                "url": parts[0] if parts else "",
                "status_code": self._extract_status(parts),
                "title": self._extract_title(parts),
                "technologies": self._extract_tech(parts),
            }
            parsed.append(entry)
        return parsed

    def _parse_bruteforced(self, bruteforced):
        """Parse bruteforced subdomains"""
        return [{"subdomain": sub.strip(), "status": "verified"} for sub in bruteforced if sub.strip()]

    def _parse_urls(self, urls):
        """Parse collected URLs"""
        return [{"url": url.strip()} for url in urls if url.strip() and "404" not in url]

    def _parse_vulnerabilities(self, vulnerabilities):
        """Parse nuclei findings"""
        parsed = []
        for vuln in vulnerabilities:
            if not vuln.strip() or "404" in vuln:
                continue

            # Try to parse as JSON
            try:
                vuln_data = json.loads(vuln)
                parsed.append({
                    "template": vuln_data.get("template-id", "unknown"),
                    "severity": vuln_data.get("info", {}).get("severity", "unknown"),
                    "name": vuln_data.get("info", {}).get("name", "unknown"),
                    "url": vuln_data.get("matched-at", ""),
                    "description": vuln_data.get("info", {}).get("description", ""),
                })
            except json.JSONDecodeError:
                # Parse plain text format
                parsed.append({
                    "raw": vuln.strip(),
                    "type": "nuclei_finding",
                })

        return parsed

    def _parse_xss(self, xss_findings):
        """Parse XSS findings"""
        parsed = []
        for finding in xss_findings:
            if not finding.strip() or "404" in finding:
                continue

            # Extract URL and payload
            url_match = re.search(r'https?://[^\s]+', finding)
            parsed.append({
                "url": url_match.group(0) if url_match else "",
                "type": "XSS",
                "evidence": finding.strip(),
            })
        return parsed

    def _parse_directories(self, directories):
        """Parse directory findings"""
        parsed = []
        for finding in directories:
            if not finding.strip() or "404" in finding:
                continue

            try:
                data = json.loads(finding)
                for result in data.get("results", []):
                    parsed.append({
                        "url": result.get("url", ""),
                        "status": result.get("status", 0),
                        "length": result.get("length", 0),
                        "words": result.get("words", 0),
                    })
            except (json.JSONDecodeError, KeyError):
                parsed.append({"raw": finding.strip()})

        return parsed

    def _extract_status(self, parts):
        """Extract status code from httpx output"""
        for part in parts:
            if "[" in part and "]" in part and any(c.isdigit() for c in part):
                match = re.search(r'\[(\d+)\]', part)
                if match:
                    code = match.group(1)
                    if code != "404":
                        return code
        return None

    def _extract_title(self, parts):
        """Extract title from httpx output"""
        for i, part in enumerate(parts):
            if "title:" in part.lower():
                return part.replace("Title:", "").replace("title:", "").strip()
        return None

    def _extract_tech(self, parts):
        """Extract technologies from httpx output"""
        for part in parts:
            if "[" in part and "]" in part and "http" not in part.lower():
                return part.strip("[]")
        return None
