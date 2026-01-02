#!/usr/bin/env python3
"""
Git Secrets Scanner - Scan git repositories for leaked secrets
"""

import argparse
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


SECRET_PATTERNS = [
    (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Password'),
    (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'API Key'),
    (r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Secret'),
    (r'["\']?token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Token'),
    (r'AKIA[A-Z0-9]{16}', 'AWS Access Key'),
    (r'-----BEGIN (RSA )?PRIVATE KEY-----', 'Private Key'),
    (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'SSH Private Key'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
    (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key'),
    (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key'),
    (r'xox[baprs]-[0-9a-zA-Z-]{10,}', 'Slack Token'),
]


@dataclass
class Secret:
    file: str
    line: int
    type: str
    value: str
    severity: str


class GitScanner:
    def __init__(self, path: str):
        self.path = path
        self.secrets: List[Secret] = []
    
    def scan(self) -> List[Secret]:
        """Scan repository for secrets"""
        for root, dirs, files in os.walk(self.path):
            # Skip .git directory
            if '.git' in dirs:
                dirs.remove('.git')
            
            for file in files:
                filepath = os.path.join(root, file)
                self.scan_file(filepath)
        
        return self.secrets
    
    def scan_file(self, filepath: str):
        """Scan a file for secrets"""
        # Skip binary files
        try:
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()
        except:
            return
        
        for i, line in enumerate(lines, 1):
            for pattern, secret_type in SECRET_PATTERNS:
                match = re.search(pattern, line, re.I)
                if match:
                    value = match.group(1) if match.lastindex else match.group(0)
                    
                    # Skip placeholders
                    if value.lower() in ['password', 'secret', 'key', 'token', 'xxx', 
                                         'changeme', 'example', 'your_key', 'your_secret']:
                        continue
                    
                    self.secrets.append(Secret(
                        file=os.path.relpath(filepath, self.path),
                        line=i,
                        type=secret_type,
                        value=self.mask(value),
                        severity='high' if 'key' in secret_type.lower() or 'private' in secret_type.lower() else 'medium'
                    ))
    
    def mask(self, value: str) -> str:
        """Mask secret value"""
        if len(value) < 8:
            return '*' * len(value)
        return value[:4] + '*' * (len(value) - 8) + value[-4:]


def print_banner():
    print(f"""{Colors.CYAN}
   ____ _ _     ____                      _       
  / ___(_) |_  / ___|  ___  ___ _ __ ___| |_ ___ 
 | |  _| | __| \___ \ / _ \/ __| '__/ _ \ __/ __|
 | |_| | | |_   ___) |  __/ (__| | |  __/ |_\__ \\
  \____|_|\__| |____/ \___|\___|_|  \___|\__|___/
{Colors.RESET}                                        v{VERSION}
""")


def main():
    parser = argparse.ArgumentParser(description="Git Secrets Scanner")
    parser.add_argument("path", nargs="?", default=".", help="Repository path")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    print_banner()
    
    if args.demo:
        print(f"{Colors.CYAN}Demo - Found Secrets:{Colors.RESET}")
        demo_secrets = [
            ("config.py", 15, "Password", "db_p****pass"),
            (".env", 3, "API Key", "sk-A****B4j8"),
            ("deploy.sh", 22, "AWS Access Key", "AKIA****P3QR"),
        ]
        for file, line, type_, value in demo_secrets:
            print(f"\n  {Colors.RED}[HIGH]{Colors.RESET} {type_}")
            print(f"    File: {file}:{line}")
            print(f"    Value: {value}")
        print(f"\n{Colors.BOLD}Total: 3 secrets found{Colors.RESET}")
        return
    
    print(f"{Colors.CYAN}[*]{Colors.RESET} Scanning {args.path}...")
    
    scanner = GitScanner(args.path)
    secrets = scanner.scan()
    
    if secrets:
        print(f"\n{Colors.RED}{Colors.BOLD}Found {len(secrets)} secrets:{Colors.RESET}")
        for s in secrets:
            color = Colors.RED if s.severity == 'high' else Colors.YELLOW
            print(f"\n  {color}[{s.severity.upper()}]{Colors.RESET} {s.type}")
            print(f"    File: {s.file}:{s.line}")
            print(f"    Value: {s.value}")
    else:
        print(f"\n{Colors.GREEN}✓ No secrets found{Colors.RESET}")


if __name__ == "__main__":
    main()
