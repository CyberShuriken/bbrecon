"""Validation utilities for BBHunt"""

import os
import re
import shutil
import subprocess
from pathlib import Path

def validate_domain(domain):
    """Validate domain format"""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def check_dependencies():
    """Check if required tools are installed"""
    from lib.config import Config

    required_tools = ["subfinder", "httpx", "nuclei", "puredns"]
    missing = []

    for tool in required_tools:
        tool_path = Config.get_tool_path(tool)

        # Check if tool exists at specified path or in PATH
        if not os.path.exists(tool_path) and not shutil.which(tool):
            missing.append(tool)

    # Check wordlists
    if not os.path.exists(Config.WORDLISTS["big"]):
        print(f"[!] Warning: Wordlist not found: {Config.WORDLISTS['big']}")

    if not os.path.exists(Config.NUCLEI_TEMPLATES):
        print(f"[!] Warning: Nuclei templates not found: {Config.NUCLEI_TEMPLATES}")

    return missing

def check_tool_version(tool_path):
    """Get tool version"""
    try:
        result = subprocess.run(
            [tool_path, "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception:
        return "unknown"

def ensure_resolvers():
    """Ensure DNS resolvers file exists in a user-writable location"""
    from pathlib import Path
    from lib.config import Config

    # Use user home directory for resolvers (avoids permission issues)
    config_dir = Path.home() / ".bbrecon"
    config_dir.mkdir(parents=True, exist_ok=True)

    resolvers_path = config_dir / "resolvers.txt"

    if not resolvers_path.exists():
        with open(resolvers_path, "w") as f:
            f.write("\n".join(Config.DNS_RESOLVERS))

    return str(resolvers_path)
