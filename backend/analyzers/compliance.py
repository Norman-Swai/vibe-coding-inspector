from __future__ import annotations

import uuid
from typing import List
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from ..schemas import Evidence, Finding, Location, ModuleName, ScanRecord, Severity, Verification


REQUIREMENTS = {
    'privacy policy': ['privacy'],
    'terms of service': ['terms', 'conditions'],
    'cookie consent': ['cookie'],
    'contact page': ['contact'],
    'about page': ['about'],
}


def run_compliance_analysis(record: ScanRecord) -> List[Finding]:
    response = requests.get(record.target_url, timeout=10)
    soup = BeautifulSoup(response.text, 'html.parser')
    href_map = {
        (anchor.get_text(' ', strip=True) + ' ' + anchor.get('href', '')).lower(): urljoin(record.target_url, anchor.get('href', ''))
        for anchor in soup.select('a[href]')
    }
    findings: List[Finding] = []
    for requirement, keywords in REQUIREMENTS.items():
        matched_url = None
        for text, href in href_map.items():
            if any(keyword in text for keyword in keywords):
                matched_url = href
                break
        if not matched_url:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    title=f'Missing or undiscoverable {requirement}',
                    category=ModuleName.compliance,
                    severity=Severity.medium,
                    verification=Verification.confirmed,
                    source_modules=[ModuleName.compliance],
                    location=Location(url=record.target_url, element='navigation'),
                    evidence=Evidence(snippet='No matching navigation or footer link was detected.', captured_output='Homepage compliance link check'),
                    description_plain=f'The inspection did not discover a clear {requirement} link from the scanned page.',
                    impact_plain='Missing trust and legal pages can reduce compliance confidence and user trust.',
                    fix_suggestion={"summary": f'Add a clearly labeled {requirement} link in the site footer or primary navigation.'},
                )
            )
    return findings
