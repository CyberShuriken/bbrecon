# BBHUNT - Bug Bounty Hunting Automation Tool

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)]()
[![Version](https://img.shields.io/badge/version-2.0.0-red.svg)]()

> Automated bug bounty reconnaissance orchestration framework. Chains industry-standard tools into a single command-line pipeline for authorized security testing.

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Use it only on systems you own or have explicit permission to test. The author is not responsible for misuse.

## 🎯 Overview

BBHUNT is a Python-based orchestrator that automates the full bug bounty reconnaissance workflow. Instead of running each tool manually, BBHUNT chains **subfinder → httpx → puredns → gau/waybackurls → nuclei → dalfox → ffuf** into a single execution with:

- Self-error handling (automatic retry on failure)
- 404 response filtering at every stage
- Structured TXT and JSON report output
- No log files, no summary spam
- Cross-tool deduplication

## ✨ Features

- **7-phase automated pipeline** — domain to report in one command
- **Self-error handling** — each tool has retry logic with timeout management
- **404 filtering** — invalid responses removed at output layer
- **Clean output** — only TXT and JSON reports, no log files
- **Cross-platform** — works on any Linux distribution (optimized for Fedora KDE)
- **Configurable** — all tool paths, wordlists, threads, and rate limits in `lib/config.py`
- **Graceful shutdown** — Ctrl+C safe
- **Dependency validation** — startup checks with install instructions

## 📋 Requirements

### System
- **OS:** Linux (tested on Fedora KDE Plasma)
- **Python:** 3.8+
- **Bash:** 4.0+

### Required Tools
| Tool | Purpose |
|------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration |
| [httpx](https://github.com/projectdiscovery/httpx) | Live host probing |
| [puredns](https://github.com/d3mondev/puredns) | DNS brute-forcing |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning |
| [gau](https://github.com/lc/gau) | Historical URL collection |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Wayback URL collection |
| [dalfox](https://github.com/hahwul/dalfox) | XSS detection |
| [ffuf](https://github.com/ffuf/ffuf) | Directory fuzzing |

### Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists) at `/usr/share/wordlists/SecLists`
- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) at `~/nuclei-templates`

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/h4ckr/bbrecon.git
cd bbrecon

# Install Python dependency
pip install -r requirements.txt

# Make executable
chmod +x bbrecon.py

# Run
python3 bbrecon.py -d example.com
```

## 📖 Usage

### Basic Scan
```bash
python3 bbrecon.py -d example.com
```

### Custom Output Directory
```bash
python3 bbrecon.py -d example.com -o ./scan_results
```

### Help
```bash
python3 bbrecon.py --help
```

## 🏗️ Architecture

BBHUNT follows a **modular pipeline architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    bbrecon.py (CLI)                      │
│              Argument parsing, entry point              │
└────────────────────────┬────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   ┌─────────┐    ┌──────────┐    ┌──────────┐
   │banner.py│    │validator │    │ runner.py│
   │ Display │    │   .py    │    │  Tool    │
   │ banner  │    │ Checks   │    │   exec   │
   └─────────┘    └──────────┘    └──────────┘
                         │                │
                         ▼                ▼
                  ┌──────────┐    ┌──────────┐
                  │ config.py│    │ parser.py│
                  │  Paths & │    │  Result  │
                  │settings  │    │parsing   │
                  └──────────┘    └──────────┘
                                       │
                                       ▼
                                ┌──────────┐
                                │reporter  │
                                │  .py     │
                                │TXT/JSON  │
                                └──────────┘
```

### Module Breakdown

| Module | Responsibility |
|--------|---------------|
| `bbrecon.py` | CLI entry, arg parsing, pipeline orchestration |
| `lib/banner.py` | ASCII art banner display |
| `lib/config.py` | Tool paths, wordlists, thread/rate configuration |
| `lib/validator.py` | Dependency checks, domain validation, resolver setup |
| `lib/runner.py` | Tool execution with retry logic, 404 filtering |
| `lib/parser.py` | Parse raw tool output into structured findings |
| `lib/reporter.py` | Generate final TXT and JSON reports |

## 🔄 Working Procedure

The tool executes a **7-phase sequential pipeline**. Each phase depends on the output of the previous one, and each has independent error handling.

### Phase 1: Subdomain Enumeration
- **Tool:** `subfinder`
- **Input:** Root domain
- **Process:** Uses passive sources to discover subdomains
- **Output:** `all_subdomains.txt`
- **404 Handling:** Not applicable (passive enumeration)

### Phase 2: Live Host Detection
- **Tool:** `httpx`
- **Input:** Subdomain list from Phase 1
- **Process:** HTTP/HTTPS probing with status code, title, and tech detection
- **Output:** `live_subdomains.txt`
- **404 Handling:** Lines containing `[404]` are filtered before saving

### Phase 3: DNS Brute-Force
- **Tools:** `puredns` + `alterx` patterns
- **Input:** Root domain
- **Process:** Permutation-based DNS resolution with public resolvers
- **Output:** `bruteforced_subdomains.txt`
- **404 Handling:** Verified against httpx, non-resolving hosts removed

### Phase 4: URL Collection
- **Tools:** `gau` + `waybackurls`
- **Input:** Live hosts from Phases 2 & 3
- **Process:** Aggregates historical URLs from Wayback Machine and other sources
- **Output:** `all_urls.txt` (deduplicated)
- **404 Handling:** URLs containing `404` removed

### Phase 5: Vulnerability Scanning
- **Tool:** `nuclei`
- **Input:** Live hosts
- **Process:** Template-based scanning across all severity levels
- **Output:** `nuclei_findings.json` + `nuclei_findings.txt`
- **404 Handling:** Findings matching `404` status filtered out

### Phase 6: XSS Detection
- **Tool:** `dalfox`
- **Input:** URLs from Phase 4
- **Process:** Reflected and DOM-based XSS analysis
- **Output:** `xss_findings.txt`
- **404 Handling:** Filtered at input and output

### Phase 7: Directory Fuzzing
- **Tool:** `ffuf`
- **Input:** Live hosts
- **Process:** Brute-force directories and files with SecLists wordlists
- **Output:** `directory_findings.txt` + per-host JSON
- **404 Handling:** Only 200, 201, 202, 203, 204, 301, 302, 307, 401, 403, 405, 500 included

### Final: Report Generation
- **Module:** `lib/reporter.py`
- **Process:** Aggregates all phase outputs, deduplicates, structures findings
- **Output:** `bbrecon_report_<timestamp>.txt` and `.json`

## 📂 Output Structure

Single folder with only files relevant for bug hunting. All intermediate/temp files go to `/tmp/bbrecon/` (auto-cleaned on system reboot).

```
output/
├── bbrecon_report_<timestamp>.txt      # Master human-readable report
├── bbrecon_report_<timestamp>.json     # Master JSON report
├── subdomains.txt                     # Phase 1: All discovered subdomains
├── live_hosts.txt                     # Phase 2: Live hosts (URL | Status | Title | Tech)
├── bruteforced_subdomains.txt         # Phase 3: New subdomains from DNS bruteforce
├── urls.txt                           # Phase 4: Historical URLs (gau + waybackurls)
├── vulnerabilities.txt                # Phase 5: Nuclei findings (Severity | Template | Name | URL)
├── xss_findings.txt                   # Phase 6: XSS candidates
└── directories.txt                    # Phase 7: Discovered directories/files
```

All per-phase `.txt` files have a header showing:
- What phase the data is from
- Generation timestamp
- Total count of entries

Intermediate files (chunks, temp inputs, raw subfinder output) are stored in `/tmp/bbrecon/` and never appear in `output/`.

## 🛡️ Error Handling Strategy

Every tool execution in `lib/runner.py` follows this pattern:

```
execute command
  ↓
success? → save output, filter 404s, return
  ↓ no
retry (up to 2 times with 2s backoff)
  ↓
still failing? → log to console, continue with empty result
```

This ensures that if one tool fails (network issues, rate limits, etc.), the pipeline continues with degraded functionality rather than crashing entirely.

## ⚙️ Configuration

Edit `lib/config.py` to customize:

```python
TOOL_PATHS = {
    "subfinder": "/home/h4ckr/go/bin/subfinder",
    "httpx": "/home/h4ckr/go/bin/httpx",
    ...
}

WORDLISTS = {
    "big": "/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt",
    "dns_wordlist": "/usr/share/wordlists/SecLists/Discovery/DNS/...",
    ...
}

HTTPX_THREADS = 100
NUCLEI_THREADS = 25
NUCLEI_RATE_LIMIT = 100
FFUF_THREADS = 40
FFUF_RATE = 100
```

## 📝 Report Formats

### TXT Report
Human-readable format with sections for each phase:
- Scan metadata (counts per phase)
- Subdomain list
- Live hosts (URL, status, title, tech)
- Bruteforced subdomains
- Collected URLs (limited to 500)
- Vulnerabilities (template, severity, URL, description)
- XSS findings (URL, evidence)
- Directory findings (URL, status, length)

### JSON Report
Structured format with metadata and per-category arrays:
```json
{
  "scan_date": "ISO timestamp",
  "target": "domain",
  "tool": "BBHUNT v2.0.0",
  "findings": {
    "scan_metadata": {...},
    "subdomains": [...],
    "live_hosts": [...],
    "bruteforced_subdomains": [...],
    "urls": [...],
    "vulnerabilities": [...],
    "xss_findings": [...],
    "directory_findings": [...]
  }
}
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open Pull Request

## 📄 License

MIT License — see [LICENSE](LICENSE) file.

## 👤 Author

**h4ckr**
- GitHub: [@h4ckr](https://github.com/h4ckr)
- HackerOne: [h4ckr](https://hackerone.com/h4ckr)

## 🙏 Acknowledgments

Built on top of these excellent open-source tools:
- [ProjectDiscovery](https://github.com/projectdiscovery) — subfinder, httpx, nuclei
- [Tomnomnom](https://github.com/tomnomnom) — waybackurls
- [lc](https://github.com/lc) — gau
- [d3mondev](https://github.com/d3mondev) — puredns
- [hahwul](https://github.com/hahwul) — dalfox
- [ffuf](https://github.com/ffuf/ffuf) — ffuf
- [Daniel Miessler](https://github.com/danielmiessler) — SecLists

---

**⚠️ Always get proper authorization before testing. Happy hunting! 🐛**
