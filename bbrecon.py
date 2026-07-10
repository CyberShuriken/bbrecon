#!/usr/bin/env python3
"""
BBHUNT - Bug Bounty Hunting Automation Tool
Author: h4ckr
Version: 2.0.0
Description: Automated bug bounty reconnaissance tool for whatnot program
"""

import sys
import os
import argparse
import json
import time
import signal
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style, init

from lib.banner import print_banner
from lib.validator import check_dependencies, validate_domain
from lib.runner import ToolRunner
from lib.parser import ResultParser
from lib.reporter import ReportGenerator
from lib.config import Config

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class BBHunt:
    def __init__(self, domain, output_dir):
        self.domain = domain
        self.output_dir = Path(output_dir)
        self.config = Config()
        self.runner = ToolRunner(self.output_dir)
        self.parser = ResultParser()
        self.reporter = ReportGenerator(self.output_dir, self.domain)

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Clean old results for fresh scan
        self._clean_old_results()

    def run(self):
        """Main execution pipeline"""
        start_time = time.time()

        try:
            self.print_step("[*] Validating target domain...")
            if not validate_domain(self.domain):
                print(f"{Fore.RED}[!] Invalid domain format: {self.domain}")
                return False

            self.print_step("[*] Checking required tools...")
            missing = check_dependencies()
            if missing:
                print(f"{Fore.RED}[!] Missing tools: {', '.join(missing)}")
                print(f"{Fore.YELLOW}[*] Install with: sudo dnf install {' '.join(missing)}")
                return False

            # Phase 1: Subdomain Enumeration
            self.print_step(f"[*] Phase 1: Enumerating subdomains for {self.domain}")
            subdomains = self.runner.enumerate_subdomains(self.domain)

            # Phase 2: Live Host Detection
            self.print_step("[*] Phase 2: Detecting live hosts")
            live_hosts = self.runner.detect_live_hosts(subdomains)

            # Phase 3: DNS Brute Force with puredns/alterx
            self.print_step("[*] Phase 3: DNS brute-forcing with permutations")
            bruteforced = self.runner.bruteforce_subdomains(self.domain, live_hosts)

            # Combine all hosts for later phases
            all_hosts = list(set(live_hosts + bruteforced))

            # Phase 4: URL Collection
            self.print_step("[*] Phase 4: Collecting historical URLs")
            urls = self.runner.collect_urls(all_hosts)

            # Phase 5: Vulnerability Scanning
            self.print_step("[*] Phase 5: Running vulnerability scans")
            vulnerabilities = self.runner.scan_vulnerabilities(all_hosts, urls)

            # Phase 6: XSS Detection
            self.print_step("[*] Phase 6: XSS detection")
            xss_findings = self.runner.detect_xss(urls)

            # Phase 7: Directory Fuzzing
            self.print_step("[*] Phase 7: Directory fuzzing")
            directories = self.runner.fuzz_directories(all_hosts)

            # Generate final reports
            self.print_step("[*] Generating reports...")
            all_findings = self.parser.consolidate_findings(
                subdomains, live_hosts, bruteforced, urls,
                vulnerabilities, xss_findings, directories
            )

            self.reporter.generate_txt_report(all_findings)
            self.reporter.generate_json_report(all_findings)

            # Cleanup intermediate chunk files
            self.runner._cleanup_chunks()

            elapsed = time.time() - start_time
            self.print_step(f"[+] Scan completed in {elapsed:.2f} seconds")
            self.print_step(f"[+] Results saved to: {self.results_dir}")

            return True

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}")
            return False

    def print_step(self, message):
        """Print formatted step message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.CYAN}[{timestamp}] {message}{Style.RESET_ALL}")

    def _clean_old_results(self):
        """Clean all old results to ensure fresh scan every run"""
        import shutil
        if self.output_dir.exists():
            # Remove all files and subdirectories (except .gitkeep) at the top level
            for item in self.output_dir.iterdir():
                if item.name == ".gitkeep":
                    continue
                try:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                except Exception:
                    pass


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="BBHUNT - Automated Bug Bounty Reconnaissance Tool",
        usage="bbrecon -d DOMAIN [-o OUTPUT_DIR]"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., whatnot.com)")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner display")

    args = parser.parse_args()

    if args.no_banner:
        os.system('clear')

    # Get absolute path for output
    output_path = Path(args.output).resolve()

    # Initialize and run BBHunt
    hunter = BBHunt(args.domain, output_path)
    success = hunter.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
