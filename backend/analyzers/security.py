from __future__ import annotations

import json
import re
import subprocess
import uuid
from pathlib import Path
from typing import List

import requests

from ..schemas import Evidence, Finding, Location, ModuleName, ScanRecord, Severity, Verification


def run_security_analysis(record: ScanRecord) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_check_response_headers(record.target_url))
    if record.repo_path:
        repo_path = Path(record.repo_path)
        findings.extend(_scan_for_secrets(repo_path))
        findings.extend(_run_npm_audit(repo_path))
    return findings


def _check_response_headers(target_url: str) -> List[Finding]:
    response = requests.get(target_url, timeout=10)
    headers = response.headers
    findings: List[Finding] = []
    required_headers = [
        ('content-security-policy', Severity.high, 'Add a Content-Security-Policy header to reduce XSS exposure.', 'CWE-693'),
        ('x-frame-options', Severity.medium, 'Add X-Frame-Options or equivalent framing control.', 'CWE-1021'),
        ('x-content-type-options', Severity.low, 'Set X-Content-Type-Options: nosniff.', 'CWE-16'),
    ]
    for header, severity, remediation, cwe_id in required_headers:
        if header not in {key.lower() for key in headers.keys()}:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    title=f'Missing security header: {header}',
                    category=ModuleName.security,
                    severity=severity,
                    verification=Verification.confirmed,
                    source_modules=[ModuleName.security],
                    location=Location(url=target_url, element='response headers'),
                    evidence=Evidence(snippet=json.dumps(dict(headers), indent=2)[:500], captured_output='HTTP response headers'),
                    description_plain=f'The response does not include the {header} header.',
                    impact_plain='Missing response hardening headers can increase exploitability or unsafe rendering behavior.',
                    cwe_id=cwe_id,
                    fix_suggestion={"summary": remediation},
                )
            )
    return findings


def _scan_for_secrets(repo_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    patterns = [
        (re.compile(r'AKIA[0-9A-Z]{16}'), 'Potential AWS access key'),
        (re.compile(r'(?i)(api[_-]?key|secret|token)\s*[:=]\s*["\'][^"\']{8,}["\']'), 'Potential hard-coded secret'),
    ]
    for path in repo_path.rglob('*'):
        if not path.is_file() or 'node_modules' in path.parts or '.git' in path.parts:
            continue
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for pattern, title in patterns:
            match = pattern.search(content)
            if match:
                line_no = content[: match.start()].count('\n') + 1
                masked = _mask(match.group(0))
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=title,
                        category=ModuleName.security,
                        severity=Severity.critical,
                        verification=Verification.hypothesis,
                        source_modules=[ModuleName.security],
                        location=Location(file=str(path), line_start=line_no, line_end=line_no),
                        evidence=Evidence(snippet=masked, captured_output='Masked potential secret'),
                        description_plain='A source file appears to contain a hard-coded credential or access token pattern.',
                        impact_plain='Secrets committed to source code can be exfiltrated and abused quickly.',
                        cwe_id='CWE-798',
                        fix_suggestion={"summary": 'Move secrets into secure environment variables or a secret manager and rotate the exposed credential.'},
                    )
                )
    return findings


def _run_npm_audit(repo_path: Path) -> List[Finding]:
    if not (repo_path / 'package.json').exists():
        return []
    try:
        completed = subprocess.run(
            ['npm', 'audit', '--json'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except Exception:
        return []
    output = completed.stdout.strip()
    if not output:
        return []
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return []
    vulnerabilities = payload.get('vulnerabilities', {})
    findings: List[Finding] = []
    for package_name, details in vulnerabilities.items():
        severity = details.get('severity', 'medium')
        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                title=f'Vulnerable dependency reported by npm audit: {package_name}',
                category=ModuleName.security,
                severity=Severity(severity if severity in Severity._value2member_map_ else 'medium'),
                verification=Verification.hypothesis,
                source_modules=[ModuleName.security],
                location=Location(file=str(repo_path / 'package.json')),
                evidence=Evidence(snippet=json.dumps(details, indent=2)[:500], captured_output='npm audit'),
                description_plain='The package manifest triggered a dependency risk in npm audit output.',
                impact_plain='Known vulnerable dependencies can expose the application to public exploits.',
                cwe_id='CWE-1104',
                fix_suggestion={"summary": 'Update or replace the affected dependency and retest the application.'},
            )
        )
    return findings


def _mask(value: str) -> str:
    if len(value) <= 8:
        return '********'
    return f'{value[:4]}…{value[-4:]}'
