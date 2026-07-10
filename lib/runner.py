"""Tool execution and orchestration module with parallel processing"""

import subprocess
import json
import time
import tempfile
import concurrent.futures
import shutil
from pathlib import Path
from colorama import Fore, Style

from lib.config import Config
from lib.validator import ensure_resolvers

class ToolRunner:
    """Executes security tools with error handling, self-recovery, and parallel execution"""

    def __init__(self, results_dir):
        self.results_dir = Path(results_dir)
        self.config = Config()
        self.max_workers = 4  # Parallel workers for I/O-bound tasks

        # Use /tmp for all intermediate files (auto-cleaned, no output clutter)
        self.tmp_dir = Path(tempfile.gettempdir()) / "bbrecon"
        self.tmp_dir.mkdir(parents=True, exist_ok=True)

    def _tmp_file(self, name):
        """Get a temp file path for intermediate use"""
        return self.tmp_dir / name

    def run_command(self, cmd, output_file=None, timeout=600, error_retry=2, check_404=True):
        """
        Execute command with error handling and self-retry logic
        Returns: list of output lines (filtered for 404s)
        """
        for attempt in range(error_retry + 1):
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False
                )

                if result.returncode == 0 or result.stdout:
                    # Optionally save raw output
                    if output_file:
                        with open(output_file, "w") as f:
                            f.write(result.stdout)

                    # Filter and return clean results
                    lines = result.stdout.splitlines()
                    if check_404:
                        lines = self._filter_output(lines)
                    return lines

            except subprocess.TimeoutExpired:
                if attempt < error_retry:
                    print(f"{Fore.YELLOW}[!] Timeout, retrying with extended timeout... ({attempt+1}/{error_retry}){Style.RESET_ALL}")
                    timeout = min(timeout * 2, 3600)  # Double timeout, max 1 hour
                    time.sleep(2)
                else:
                    print(f"{Fore.RED}[!] Command timed out after retries: {cmd[:60]}...{Style.RESET_ALL}")
                    return []

            except Exception as e:
                if attempt < error_retry:
                    print(f"{Fore.YELLOW}[!] Error occurred, retrying... ({attempt+1}/{error_retry}){Style.RESET_ALL}")
                    time.sleep(2)
                else:
                    print(f"{Fore.RED}[!] Command failed: {str(e)}{Style.RESET_ALL}")
                    return []

        return []

    def _filter_output(self, lines):
        """Filter out 404 and invalid responses"""
        filtered = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Skip 404 status codes
            if "404" in line and "status" in line.lower():
                continue
            if "[404]" in line or "[not found]" in line.lower():
                continue
            filtered.append(line)
        return filtered

    def _dedupe_subdomains(self, subdomains):
        """Deduplicate subdomains preserving order"""
        seen = set()
        unique = []
        for sub in subdomains:
            sub_clean = sub.strip().lower().rstrip('.')
            if sub_clean and sub_clean not in seen:
                seen.add(sub_clean)
                unique.append(sub_clean)
        return unique

    def _dedupe_urls(self, urls):
        """Deduplicate URLs - normalize and remove duplicates"""
        seen = set()
        unique = []
        for url in urls:
            url_clean = url.strip()
            if not url_clean:
                continue
            # Normalize: lowercase host, remove trailing slash, remove fragments
            normalized = url_clean.split('#')[0].rstrip('/')
            # Lowercase only the host part
            if '://' in normalized:
                scheme, rest = normalized.split('://', 1)
                if '/' in rest:
                    host, path = rest.split('/', 1)
                    path = '/' + path
                else:
                    host, path = rest, ''
                normalized = f"{scheme}://{host.lower()}{path}"

            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(url_clean)
        return unique

    def _dedupe_vulns(self, findings):
        """Deduplicate vulnerability findings by URL + template/evidence"""
        seen = set()
        unique = []
        for finding in findings:
            finding_clean = finding.strip()
            if not finding_clean:
                continue
            # Try to extract a unique key for nuclei JSON findings
            key = None
            try:
                data = json.loads(finding_clean)
                if isinstance(data, dict):
                    # Nuclei JSON format
                    template = data.get('template-id', '')
                    matched = data.get('matched-at', '')
                    key = f"{template}::{matched}"
            except (json.JSONDecodeError, ValueError):
                # Plain text - use the full line as key
                key = finding_clean

            if key and key not in seen:
                seen.add(key)
                unique.append(finding_clean)
            elif not key:
                unique.append(finding_clean)
        return unique

    def _save_human_readable(self, items, filename, header):
        """
        Save items to a single human-readable .txt file in results_dir
        Format: header comment + one item per line
        """
        output_file = self.results_dir / filename

        with open(output_file, "w") as f:
            # Human-readable header
            f.write(f"# {header}\n")
            f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total: {len(items)} entries\n")
            f.write("# " + "=" * 70 + "\n\n")

            if not items:
                f.write("# No results found\n")
            else:
                for item in items:
                    # For nuclei JSON output, pretty-print if possible
                    if isinstance(item, str) and item.strip().startswith('{'):
                        try:
                            data = json.loads(item)
                            # Extract human-readable fields
                            template = data.get('template-id', 'unknown')
                            severity = data.get('info', {}).get('severity', 'unknown')
                            name = data.get('info', {}).get('name', template)
                            url = data.get('matched-at', data.get('host', ''))
                            description = data.get('info', {}).get('description', '')

                            f.write(f"# Severity: {severity.upper()}\n")
                            f.write(f"# Template: {template}\n")
                            f.write(f"# Name: {name}\n")
                            f.write(f"# URL: {url}\n")
                            if description:
                                f.write(f"# Description: {description}\n")
                            f.write("---\n")
                            continue
                        except (json.JSONDecodeError, ValueError):
                            pass
                    f.write(f"{item}\n")

        return output_file

    def enumerate_subdomains(self, domain):
        """Phase 1: Subdomain enumeration using subfinder"""
        # Use /tmp for raw subfinder output
        tmp_output = self._tmp_file(f"subfinder_{domain}.txt")
        cmd = f"{self.config.get_tool_path('subfinder')} -d {domain} -all -silent -timeout 10"

        print(f"  -> Running subfinder...")
        raw_subdomains = self.run_command(cmd, tmp_output, timeout=300)

        # Deduplicate subdomains
        subdomains = self._dedupe_subdomains(raw_subdomains)

        # Save human-readable output
        self._save_human_readable(
            subdomains,
            f"subdomains.txt",
            f"Subdomains discovered for {domain}"
        )

        print(f"  -> Found {len(subdomains)} unique subdomains")
        return subdomains

    def detect_live_hosts(self, subdomains):
        """Phase 2: Live host detection using httpx (chunked for speed)"""
        if not subdomains:
            return []

        # Dedupe input subdomains first
        subdomains = self._dedupe_subdomains(subdomains)

        # Split into chunks to avoid timeout on large lists
        chunk_size = 100
        chunks = [subdomains[i:i+chunk_size] for i in range(0, len(subdomains), chunk_size)]

        all_live_data = []
        for i, chunk in enumerate(chunks):
            # Create temp input file
            input_file = self._tmp_file(f"httpx_input_{i}.txt")
            with open(input_file, "w") as f:
                f.write("\n".join(chunk))

            cmd = (
                f"{self.config.get_tool_path('httpx')} "
                f"-l {input_file} "
                f"-silent "
                f"-status-code "
                f"-title "
                f"-tech-detect "
                f"-follow-redirects "
                f"-threads {self.config.HTTPX_THREADS} "
                f"-timeout {self.config.HTTPX_TIMEOUT} "
                f"-retries 1 "
                f"-no-color"
            )

            print(f"  -> Running httpx probe (batch {i+1}/{len(chunks)})...")
            chunk_data = self.run_command(cmd, timeout=300)
            all_live_data.extend(chunk_data)

        # Dedupe raw httpx output
        all_live_data = list(dict.fromkeys(all_live_data))  # Preserve order

        # Extract clean URLs and human-readable info
        live_urls = []
        seen_urls = set()
        live_human_readable = []

        for line in all_live_data:
            if "[404]" in line:
                continue
            parts = line.split()
            if parts:
                url = parts[0].lower().rstrip('/')
                if url.startswith("http") and url not in seen_urls:
                    seen_urls.add(url)
                    live_urls.append(parts[0])
                    # Keep the full httpx output (URL, status, title, tech) for human readability
                    live_human_readable.append(line)

        # Save human-readable live hosts (with status, title, tech)
        self._save_human_readable(
            live_human_readable,
            "live_hosts.txt",
            "Live Hosts (URL | Status | Title | Technologies)"
        )

        print(f"  -> Found {len(live_urls)} unique live hosts")
        return live_urls

    def bruteforce_subdomains(self, domain, live_hosts):
        """Phase 3: DNS brute-force with puredns (optimized for speed)"""
        # Get resolvers
        resolvers = ensure_resolvers()

        # Use a smaller wordlist for faster bruteforcing
        wordlist = self.config.get_wordlist("alterx_pattern")  # 5000 words
        if not wordlist:
            wordlist = self.config.get_wordlist("dns_wordlist")
        if not wordlist:
            print(f"{Fore.YELLOW}[!] DNS wordlist not found, skipping bruteforce{Style.RESET_ALL}")
            return []

        # puredns with optimized flags for speed
        cmd = (
            f"{self.config.get_tool_path('puredns')} bruteforce "
            f"{wordlist} {domain} "
            f"-r {resolvers} "
            f"--resolvers-trusted {resolvers} "
            f"-q "
            f"--rate-limit-trusted 500 "
            f"-t 100 "
            f"--wildcard-tests 50"
        )

        print(f"  -> Running puredns bruteforce (optimized)...")
        raw_bruteforced = self.run_command(cmd, timeout=600)

        # Deduplicate against existing live hosts to avoid re-scanning
        existing_hosts = set()
        for host in live_hosts:
            host_clean = host.lower().replace("https://", "").replace("http://", "").rstrip('/')
            existing_hosts.add(host_clean)

        bruteforced_raw = []
        for sub in raw_bruteforced:
            sub_clean = sub.strip().lower().rstrip('.')
            # Skip if already in live hosts
            if sub_clean and sub_clean not in existing_hosts:
                bruteforced_raw.append(sub_clean)

        # Verify with httpx in parallel batches
        if bruteforced_raw:
            bruteforced_raw = self._dedupe_subdomains(bruteforced_raw)
            verified = self._verify_hosts_parallel(bruteforced_raw, "bruteforced")

            # Dedupe final verified list against live_hosts
            final_unique = []
            for host in verified:
                host_clean = host.lower().rstrip('/')
                if host_clean not in existing_hosts:
                    final_unique.append(host)
                    existing_hosts.add(host_clean)

            # Save human-readable output
            if final_unique:
                # Convert URLs to bare subdomains for readability
                display_subs = []
                for url in final_unique:
                    sub = url.replace("https://", "").replace("http://", "").rstrip('/')
                    display_subs.append(sub)
                self._save_human_readable(
                    display_subs,
                    "bruteforced_subdomains.txt",
                    f"Subdomains discovered via DNS bruteforce (new, not in passive enumeration)"
                )

            print(f"  -> Found {len(final_unique)} new unique bruteforced hosts")
            return final_unique

        return []

    def _verify_hosts_parallel(self, hosts, prefix):
        """Verify hosts using httpx in parallel batches"""
        # Dedupe input hosts first
        hosts = self._dedupe_urls(hosts)

        chunk_size = 50
        chunks = [hosts[i:i+chunk_size] for i in range(0, len(hosts), chunk_size)]

        def verify_chunk(chunk_data):
            idx, chunk = chunk_data
            input_file = self._tmp_file(f"{prefix}_verify_{idx}.txt")

            with open(input_file, "w") as f:
                f.write("\n".join(chunk))

            cmd = (
                f"{self.config.get_tool_path('httpx')} "
                f"-l {input_file} "
                f"-silent "
                f"-threads {self.config.HTTPX_THREADS} "
                f"-timeout 5 "
                f"-retries 1 "
                f"-no-color"
            )

            return self.run_command(cmd, timeout=180, check_404=False)

        # Run verification in parallel
        verified_hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(verify_chunk, (i, chunk)): i for i, chunk in enumerate(chunks)}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    for line in result:
                        if line.startswith("http"):
                            verified_hosts.append(line)
                except Exception as e:
                    print(f"{Fore.RED}[!] Verification error: {e}{Style.RESET_ALL}")

        # Deduplicate (preserving order)
        verified_hosts = self._dedupe_urls(verified_hosts)
        return verified_hosts

    def collect_urls(self, hosts):
        """Phase 4: URL collection using gau and waybackurls IN PARALLEL (chunked per tool)"""
        if not hosts:
            return []

        # Dedupe input hosts
        hosts = self._dedupe_urls(hosts)

        # Split hosts into chunks to avoid timeout on large lists
        chunk_size = 10
        host_chunks = [hosts[i:i+chunk_size] for i in range(0, len(hosts), chunk_size)]

        def run_gau_chunk(chunk):
            """Run gau on a single chunk of hosts"""
            input_file = self._tmp_file(f"gau_input_{id(chunk)}.txt")
            with open(input_file, "w") as f:
                f.write("\n".join(chunk))
            cmd = f"cat {input_file} | {self.config.get_tool_path('gau')} --threads 5 --timeout 30"
            return self.run_command(cmd, timeout=300, error_retry=1)

        def run_wayback_chunk(chunk):
            """Run waybackurls on a single chunk of hosts"""
            input_file = self._tmp_file(f"wayback_input_{id(chunk)}.txt")
            with open(input_file, "w") as f:
                f.write("\n".join(chunk))
            cmd = f"cat {input_file} | {self.config.get_tool_path('waybackurls')} -no-subs"
            return self.run_command(cmd, timeout=300, error_retry=1)

        # Run both tools in parallel, chunked across all host chunks
        all_gau_urls = []
        all_wb_urls = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            # Submit all chunks for both tools in parallel
            gau_futures = {executor.submit(run_gau_chunk, chunk): idx for idx, chunk in enumerate(host_chunks)}
            wb_futures = {executor.submit(run_wayback_chunk, chunk): idx for idx, chunk in enumerate(host_chunks)}

            # Collect gau results
            print(f"  -> Running gau ({len(host_chunks)} batch(es))...")
            for future in concurrent.futures.as_completed(gau_futures):
                try:
                    result = future.result(timeout=300)
                    all_gau_urls.extend(result)
                except concurrent.futures.TimeoutError:
                    print(f"{Fore.YELLOW}[!] gau chunk timed out, skipping{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] gau error: {e}{Style.RESET_ALL}")

            # Collect wayback results
            print(f"  -> Running waybackurls ({len(host_chunks)} batch(es))...")
            for future in concurrent.futures.as_completed(wb_futures):
                try:
                    result = future.result(timeout=300)
                    all_wb_urls.extend(result)
                except concurrent.futures.TimeoutError:
                    print(f"{Fore.YELLOW}[!] waybackurls chunk timed out, skipping{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] waybackurls error: {e}{Style.RESET_ALL}")

        # Merge and deduplicate (with URL normalization)
        all_urls = self._dedupe_urls(all_gau_urls + all_wb_urls)

        # Filter 404s
        filtered_urls = [url for url in all_urls if "404" not in url]

        # Save human-readable
        if filtered_urls:
            self._save_human_readable(
                filtered_urls,
                "urls.txt",
                "Historical URLs collected (gau + waybackurls)"
            )

        print(f"  -> Collected {len(filtered_urls)} unique URLs")
        return filtered_urls

    def scan_vulnerabilities(self, hosts, urls):
        """Phase 5: Vulnerability scanning with nuclei (chunked)"""
        if not hosts:
            return []

        # Dedupe input hosts
        hosts = self._dedupe_urls(hosts)

        # Split hosts into chunks to avoid timeout
        chunk_size = 50
        chunks = [hosts[i:i+chunk_size] for i in range(0, len(hosts), chunk_size)]

        all_findings = []
        for i, chunk in enumerate(chunks):
            input_file = self._tmp_file(f"nuclei_input_{i}.txt")
            with open(input_file, "w") as f:
                f.write("\n".join(chunk))

            cmd = (
                f"{self.config.get_tool_path('nuclei')} "
                f"-l {input_file} "
                f"-t {self.config.NUCLEI_TEMPLATES} "
                f"-severity critical,high,medium,low,info "
                f"-silent "
                f"-c {self.config.NUCLEI_THREADS} "
                f"-rate-limit {self.config.NUCLEI_RATE_LIMIT} "
                f"-timeout 10 "
                f"-retries 1 "
                f"-no-color"
            )

            print(f"  -> Running nuclei (batch {i+1}/{len(chunks)})...")
            findings = self.run_command(cmd, timeout=900)
            all_findings.extend(findings)

        # Deduplicate findings
        all_findings = self._dedupe_vulns(all_findings)

        # Filter 404s
        filtered_findings = [f for f in all_findings if "404" not in f]

        # Save human-readable
        if filtered_findings:
            self._save_human_readable(
                filtered_findings,
                "vulnerabilities.txt",
                "Vulnerabilities found by nuclei templates"
            )

        print(f"  -> Found {len(filtered_findings)} unique potential vulnerabilities")
        return filtered_findings

    def detect_xss(self, urls):
        """Phase 6: XSS detection with dalfox (chunked)"""
        if not urls:
            return []

        # Dedupe input URLs
        urls = self._dedupe_urls(urls)

        # Limit and chunk URLs
        target_urls = urls[:500]
        chunk_size = 100
        chunks = [target_urls[i:i+chunk_size] for i in range(0, len(target_urls), chunk_size)]

        all_xss = []
        for i, chunk in enumerate(chunks):
            input_file = self._tmp_file(f"xss_input_{i}.txt")
            with open(input_file, "w") as f:
                f.write("\n".join(chunk))

            cmd = (
                f"{self.config.get_tool_path('dalfox')} file {input_file} "
                f"--silent "
                f"--no-color "
                f"--no-spinner "
                f"--timeout 10 "
                f"--worker 10"
            )

            print(f"  -> Running dalfox (batch {i+1}/{len(chunks)})...")
            xss_results = self.run_command(cmd, timeout=300)
            all_xss.extend(xss_results)

        # Deduplicate XSS findings (by URL + payload)
        seen_xss = set()
        unique_xss = []
        for finding in all_xss:
            finding_clean = finding.strip()
            if not finding_clean:
                continue
            # Extract URL as key (everything before first space or [POC])
            url_key = finding_clean.split(' ')[0].split('[')[0].lower().rstrip('/')
            if url_key and url_key not in seen_xss:
                seen_xss.add(url_key)
                unique_xss.append(finding_clean)

        all_xss = unique_xss

        # Filter 404s
        filtered_xss = [x for x in all_xss if "404" not in x]

        # Save human-readable
        if filtered_xss:
            self._save_human_readable(
                filtered_xss,
                "xss_findings.txt",
                "XSS vulnerabilities (reflected/stored)"
            )

        print(f"  -> Found {len(filtered_xss)} unique XSS candidates")
        return filtered_xss

    def fuzz_directories(self, hosts):
        """Phase 7: Directory fuzzing with ffuf (PARALLEL across hosts)"""
        if not hosts:
            return []

        # Dedupe hosts
        hosts = self._dedupe_urls(hosts)

        wordlist = self.config.get_wordlist("big")
        if not wordlist:
            print(f"{Fore.YELLOW}[!] Directory wordlist not found, skipping{Style.RESET_ALL}")
            return []

        # Limit to top hosts for performance
        target_hosts = hosts[:15]

        def fuzz_host(host):
            """Fuzz a single host"""
            # Use /tmp for ffuf output
            host_safe = host.replace("https://", "").replace("http://", "").replace("/", "_")[:50]
            tmp_output = self._tmp_file(f"ffuf_{host_safe}.json")

            cmd = (
                f"{self.config.get_tool_path('ffuf')} "
                f"-u {host}/FUZZ "
                f"-w {wordlist} "
                f"-mc 200,201,202,203,204,301,302,307,401,403,405,500 "
                f"-t {self.config.FFUF_THREADS} "
                f"-rate {self.config.FFUF_RATE} "
                f"-o {tmp_output} "
                f"-of json "
                f"-s "
                f"-timeout 10"
            )

            return host, self.run_command(cmd, timeout=300, error_retry=1)

        # Run ffuf in parallel across hosts
        all_findings = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(fuzz_host, host): host for host in target_hosts}
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                try:
                    host_name, findings = future.result(timeout=300)
                    # Filter 404s
                    filtered = [f for f in findings if "404" not in f]
                    all_findings.extend(filtered)
                    print(f"  -> Completed {host_name}")
                except concurrent.futures.TimeoutError:
                    print(f"  -> {Fore.YELLOW}Skipped {host} (timeout){Style.RESET_ALL}")
                except Exception as e:
                    print(f"  -> {Fore.RED}Error on {host}: {e}{Style.RESET_ALL}")

        # Deduplicate directory findings (by URL)
        seen_dirs = set()
        unique_dirs = []
        for finding in all_findings:
            finding_clean = finding.strip()
            if not finding_clean:
                continue
            # Extract URL (first field) as key
            url_key = finding_clean.split()[0].lower() if finding_clean else ""
            if url_key and url_key not in seen_dirs:
                seen_dirs.add(url_key)
                unique_dirs.append(finding_clean)

        all_findings = unique_dirs

        # Save human-readable
        if all_findings:
            self._save_human_readable(
                all_findings,
                "directories.txt",
                "Discovered directories and files (200/301/302/403/etc)"
            )

        print(f"  -> Found {len(all_findings)} unique directory findings")
        return all_findings
