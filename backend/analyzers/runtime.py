from __future__ import annotations

import re
import uuid
from collections import deque
from typing import List, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from ..schemas import Evidence, Finding, Location, ModuleName, ScanRecord, Severity, Verification


def run_runtime_analysis(record: ScanRecord) -> List[Finding]:
    session = requests.Session()
    queue = deque([record.target_url])
    visited: Set[str] = set()
    findings: List[Finding] = []
    root_host = urlparse(record.target_url).netloc

    while queue and len(visited) < 8:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)

        response = session.get(current, timeout=10)
        content_type = response.headers.get('content-type', '')
        if 'text/html' not in content_type:
            continue
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        if not soup.title or not soup.title.text.strip():
            findings.append(
                _finding(
                    title='Page is missing a descriptive title',
                    severity=Severity.low,
                    verification=Verification.confirmed,
                    url=current,
                    description='The page does not expose a meaningful <title> element.',
                    impact='Users and automated tools may struggle to identify the page context.',
                    snippet=str(soup.head)[:500] if soup.head else '<head> missing',
                    remediation='Add a unique, descriptive <title> tag for each page.',
                )
            )

        unlabeled_inputs = []
        for control in soup.select('input, textarea, select'):
            if control.get('type') in {'hidden', 'submit', 'button'}:
                continue
            control_id = control.get('id')
            has_label = bool(control.get('aria-label') or control.get('aria-labelledby'))
            if control_id and soup.find('label', attrs={'for': control_id}):
                has_label = True
            if not has_label:
                unlabeled_inputs.append(str(control)[:200])
        if unlabeled_inputs:
            findings.append(
                _finding(
                    title='Form controls are missing labels',
                    severity=Severity.medium,
                    verification=Verification.confirmed,
                    url=current,
                    description='Interactive form controls were found without associated labels or aria labels.',
                    impact='This breaks accessibility and may confuse users during data entry.',
                    snippet='\n'.join(unlabeled_inputs[:3]),
                    remediation='Associate each interactive form control with a visible label or ARIA label.',
                )
            )

        text = soup.get_text(' ', strip=True)
        if re.search(r'exception|stack trace|undefined is not a function', text, flags=re.I):
            findings.append(
                _finding(
                    title='Runtime error text is visible in the page body',
                    severity=Severity.high,
                    verification=Verification.hypothesis,
                    url=current,
                    description='Page content contains error-like text indicating a broken runtime state.',
                    impact='Users may experience broken flows or application instability.',
                    snippet=text[:400],
                    remediation='Investigate the failing route and replace raw runtime errors with resilient UI states.',
                )
            )

        for link in soup.select('a[href]'):
            href = link.get('href', '').strip()
            absolute = urljoin(current, href)
            parsed = urlparse(absolute)
            if parsed.scheme not in {'http', 'https'}:
                continue
            if parsed.netloc == root_host and absolute not in visited and len(queue) + len(visited) < 12:
                queue.append(absolute)

    return findings


def _finding(
    *,
    title: str,
    severity: Severity,
    verification: Verification,
    url: str,
    description: str,
    impact: str,
    snippet: str,
    remediation: str,
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        title=title,
        category=ModuleName.runtime,
        severity=severity,
        verification=verification,
        source_modules=[ModuleName.runtime],
        location=Location(url=url, element='document'),
        evidence=Evidence(snippet=snippet, captured_output='Passive HTML inspection'),
        description_plain=description,
        impact_plain=impact,
        fix_suggestion={"summary": remediation},
    )
