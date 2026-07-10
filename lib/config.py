"""Configuration management for BBHunt"""

import os
from pathlib import Path

class Config:
    """Central configuration for BBHunt tool"""

    # Tool paths (Fedora KDE Plasma - Go binaries location)
    TOOL_PATHS = {
        "subfinder": "/home/h4ckr/go/bin/subfinder",
        "httpx": "/home/h4ckr/go/bin/httpx",
        "puredns": "/home/h4ckr/go/bin/puredns",
        "nuclei": "/home/h4ckr/go/bin/nuclei",
        "gau": "/home/h4ckr/go/bin/gau",
        "waybackurls": "/home/h4ckr/go/bin/waybackurls",
        "dalfox": "/home/h4ckr/go/bin/dalfox",
        "ffuf": "/home/h4ckr/go/bin/ffuf",
    }

    # Wordlist locations
    WORDLISTS = {
        "big": "/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt",
        "alterx_pattern": "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
        "dns_wordlist": "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
        "resolvers": "/usr/share/wordlists/SecLists/Discovery/DNS/resolvers.txt",
    }

    # Nuclei templates
    NUCLEI_TEMPLATES = "/home/h4ckr/nuclei-templates"

    # Tool-specific configurations
    SUBDOMAIN_THREADS = 50
    HTTPX_THREADS = 100
    HTTPX_TIMEOUT = 10
    NUCLEI_THREADS = 25
    NUCLEI_RATE_LIMIT = 100
    FFUF_THREADS = 40
    FFUF_RATE = 100

    # Output settings
    OUTPUT_FORMATS = ["txt", "json"]
    FILTER_404 = True

    # DNS resolvers (public)
    DNS_RESOLVERS = [
        "1.1.1.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "149.112.112.112",
    ]

    @classmethod
    def get_tool_path(cls, tool_name):
        """Get tool executable path"""
        return cls.TOOL_PATHS.get(tool_name, tool_name)

    @classmethod
    def get_wordlist(cls, name):
        """Get wordlist path"""
        path = cls.WORDLISTS.get(name)
        if path and os.path.exists(path):
            return path
        return None
