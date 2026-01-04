"""Git Secrets Scanner - Output formatting"""

from typing import List, Dict
from .constants import VERSION, Colors
from .scanner import Finding


def print_banner():
    print(f"""{Colors.CYAN}
   ____ _ _     ____                     _       
  / ___(_) |_  / ___|  ___  ___ _ __ ___| |_ ___ 
 | |  _| | __| \\___ \\ / _ \\/ __| '__/ _ \\ __/ __|
 | |_| | | |_   ___) |  __/ (__| | |  __/ |_\\__ \\
  \\____|_|\\__| |____/ \\___|\\___|_|  \\___|\\__|___/
  ____                                  
 / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
  ___) | (_| (_| | | | | | | |  __/ |   
 |____/ \\___\\__,_|_| |_|_| |_|\\___|_|   
{Colors.RESET}                                 v{VERSION}
""")


def print_findings(findings: List[Finding]):
    if not findings:
        print(f"{Colors.GREEN}No secrets found!{Colors.RESET}")
        return
    
    print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}Findings ({len(findings)}){Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
    
    for finding in findings:
        severity_color = {
            'critical': Colors.RED,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.DIM
        }.get(finding.severity, Colors.DIM)
        
        print(f"\n{severity_color}[{finding.severity.upper()}]{Colors.RESET} {finding.description}")
        print(f"  File: {finding.file}:{finding.line_number}")
        print(f"  Type: {finding.secret_type}")
        print(f"  Match: {Colors.DIM}{finding.match}{Colors.RESET}")


def print_summary(summary: Dict):
    print(f"\n{Colors.CYAN}{'─' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
    
    print(f"  Files scanned: {summary['files_scanned']}")
    print(f"  Total findings: {summary['total_findings']}")
    
    if summary['by_severity']:
        print(f"\n  By Severity:")
        for sev, count in summary['by_severity'].items():
            if count > 0:
                color = Colors.RED if sev in ['critical', 'high'] else Colors.YELLOW if sev == 'medium' else Colors.DIM
                print(f"    {color}{sev.upper()}: {count}{Colors.RESET}")
