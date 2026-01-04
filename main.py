#!/usr/bin/env python3
"""Git Secrets Scanner - Entry point"""

import argparse
import json
from dataclasses import asdict

from src import (
    VERSION, Colors, SecretsScanner,
    print_banner, print_findings, print_summary
)


def demo_mode():
    print(f"{Colors.CYAN}Running demo scan on sample data...{Colors.RESET}\n")
    
    # Create sample findings
    sample_findings = [
        {
            'file': 'config/settings.py',
            'line_number': 15,
            'secret_type': 'aws_access_key',
            'severity': 'critical',
            'description': 'AWS Access Key ID',
            'match': 'AKIA****EXAMPLE****'
        },
        {
            'file': '.env',
            'line_number': 3,
            'secret_type': 'github_token',
            'severity': 'critical',
            'description': 'GitHub Personal Access Token',
            'match': 'ghp_****xxxx****xxxx'
        },
        {
            'file': 'src/api.js',
            'line_number': 42,
            'secret_type': 'google_api_key',
            'severity': 'high',
            'description': 'Google API Key',
            'match': 'AIza****DEMO****'
        }
    ]
    
    print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}Demo Findings{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
    
    for f in sample_findings:
        color = Colors.RED if f['severity'] == 'critical' else Colors.YELLOW
        print(f"\n{color}[{f['severity'].upper()}]{Colors.RESET} {f['description']}")
        print(f"  File: {f['file']}:{f['line_number']}")
        print(f"  Match: {Colors.DIM}{f['match']}{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}{'─' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary{Colors.RESET}")
    print(f"  Files scanned: 127")
    print(f"  Total findings: 3")
    print(f"  {Colors.RED}CRITICAL: 2{Colors.RESET}")
    print(f"  {Colors.YELLOW}HIGH: 1{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Git Secrets Scanner - Find exposed secrets in code"
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--demo", action="store_true", help="Run demo mode")
    parser.add_argument("--version", action="version", version=f"v{VERSION}")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    print(f"Scanning: {args.path}\n")
    
    scanner = SecretsScanner(args.path, verbose=args.verbose)
    findings = scanner.scan()
    summary = scanner.get_summary()
    
    print_findings(findings)
    print_summary(summary)
    
    if args.output:
        output = {
            'summary': summary,
            'findings': [asdict(f) for f in findings]
        }
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\n{Colors.GREEN}Results saved to: {args.output}{Colors.RESET}")


if __name__ == "__main__":
    main()
