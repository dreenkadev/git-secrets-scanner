"""Git Secrets Scanner - Core scanner"""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Optional

from .constants import SECRET_PATTERNS, IGNORE_PATTERNS


@dataclass
class Finding:
    file: str
    line_number: int
    secret_type: str
    severity: str
    description: str
    match: str
    context: str


class SecretsScanner:
    def __init__(self, path: str, verbose: bool = False):
        self.path = Path(path)
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.files_scanned = 0
        self.compiled_patterns = self._compile_patterns()
        self.ignore_patterns = [re.compile(p) for p in IGNORE_PATTERNS]
        
    def _compile_patterns(self) -> Dict:
        compiled = {}
        for name, data in SECRET_PATTERNS.items():
            compiled[name] = {
                'regex': re.compile(data['pattern']),
                'severity': data['severity'],
                'description': data['description']
            }
        return compiled
    
    def should_ignore(self, filepath: str) -> bool:
        for pattern in self.ignore_patterns:
            if pattern.search(filepath):
                return True
        return False
    
    def scan_file(self, filepath: Path) -> List[Finding]:
        findings = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return findings
        
        for line_num, line in enumerate(lines, 1):
            for name, data in self.compiled_patterns.items():
                matches = data['regex'].finditer(line)
                for match in matches:
                    matched_text = match.group()
                    # Mask the secret for display
                    if len(matched_text) > 10:
                        masked = matched_text[:4] + '*' * (len(matched_text) - 8) + matched_text[-4:]
                    else:
                        masked = matched_text[:2] + '*' * (len(matched_text) - 2)
                    
                    finding = Finding(
                        file=str(filepath),
                        line_number=line_num,
                        secret_type=name,
                        severity=data['severity'],
                        description=data['description'],
                        match=masked,
                        context=line.strip()[:80]
                    )
                    findings.append(finding)
        
        return findings
    
    def scan(self) -> List[Finding]:
        self.findings = []
        self.files_scanned = 0
        
        if self.path.is_file():
            self.findings.extend(self.scan_file(self.path))
            self.files_scanned = 1
        else:
            for root, dirs, files in os.walk(self.path):
                # Skip ignored directories
                dirs[:] = [d for d in dirs if not self.should_ignore(os.path.join(root, d))]
                
                for filename in files:
                    filepath = Path(root) / filename
                    if self.should_ignore(str(filepath)):
                        continue
                    
                    file_findings = self.scan_file(filepath)
                    self.findings.extend(file_findings)
                    self.files_scanned += 1
        
        return self.findings
    
    def get_summary(self) -> Dict:
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        type_count = {}
        
        for finding in self.findings:
            severity_count[finding.severity] = severity_count.get(finding.severity, 0) + 1
            type_count[finding.secret_type] = type_count.get(finding.secret_type, 0) + 1
        
        return {
            'files_scanned': self.files_scanned,
            'total_findings': len(self.findings),
            'by_severity': severity_count,
            'by_type': type_count
        }
