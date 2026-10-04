from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, List, Optional, Tuple
from urllib.parse import urlparse

from ..schemas import ActivityKind, Finding, Location, ModuleName, Severity, Verification
from .common import AnalyzerResult, Rule, element_line, new_finding, plural
from .web import Anchor, CrawlResult

if TYPE_CHECKING:
    from ..context import ScanContext

MODULE = ModuleName.compliance


@dataclass(frozen=True)
class Requirement:
    name: str
    keywords: Tuple[str, ...]
    severity: Severity
    why: str


REQUIREMENTS = [
    Requirement('privacy policy', ('privacy',), Severity.medium, 'Privacy laws such as GDPR and CCPA require a privacy notice whenever personal data, including analytics, is collected.'),
    Requirement('terms of service', ('terms', 'conditions', 'tos'), Severity.low, 'Terms set the rules for using the service and limit liability.'),
    Requirement('contact information', ('contact', 'support', 'mailto', 'impressum'), Severity.low, 'Users and regulators expect a way to reach the operator.'),
    Requirement('about page', ('about',), Severity.info, 'An about page tells visitors who runs the site, which builds trust.'),
]

MISSING_LINK = Rule(
    title='Missing link',
    severity=Severity.medium,
    verification=Verification.confirmed,
    check='Link text and URLs on every crawled page are searched for the requirement keywords.',
    description='No link to this page was found on any crawled page.',
    impact='Visitors cannot find the information, which reduces trust and can breach legal requirements.',
    fix='Add a clearly labelled link in the site footer or main navigation.',
)
COOKIES_WITHOUT_CONSENT = Rule(
    title='Cookies or trackers without a visible consent mechanism',
    severity=Severity.medium,
    verification=Verification.hypothesis,
    check='If crawled pages set cookies or load known analytics/ad trackers, their HTML must reference a consent manager or a cookie notice.',
    description='The site sets cookies or loads trackers, but no consent banner or cookie notice was found in the page HTML.',
    impact='Non-essential cookies set before consent breach ePrivacy/GDPR rules in many regions.',
    fix='Add a consent banner that blocks non-essential cookies and trackers until the visitor agrees, and link a cookie policy.',
)

TRACKERS = {
    'googletagmanager.com': 'Google Tag Manager',
    'google-analytics.com': 'Google Analytics',
    'connect.facebook.net': 'Meta Pixel',
    'static.hotjar.com': 'Hotjar',
    'cdn.segment.com': 'Segment',
    'clarity.ms': 'Microsoft Clarity',
    'snap.licdn.com': 'LinkedIn Insight',
    'analytics.tiktok.com': 'TikTok Pixel',
    'js.hs-scripts.com': 'HubSpot',
    'cdn.mxpnl.com': 'Mixpanel',
    'doubleclick.net': 'Google Ads',
}
CONSENT_MARKERS = re.compile(
    r'cookiebot|onetrust|cookielaw|cookieconsent|cookie-consent|cookie_consent|cookie-banner|cookie-notice|cookieyes|osano|termly|iubenda|didomi|usercentrics|quantcast|klaro|trustarc|consentmanager|complianz',
    re.I,
)


def _tokens(anchor: Anchor) -> set:
    return set(re.split(r'[^a-z0-9]+', f'{anchor.text} {anchor.raw_href}'.lower())) - {''}


def _match(requirement: Requirement, anchors: List[Anchor]) -> Optional[Anchor]:
    for anchor in anchors:
        tokens = _tokens(anchor)
        if any(keyword in tokens or (len(keyword) > 5 and keyword in ' '.join(tokens)) for keyword in requirement.keywords):
            return anchor
    return None


def _links_evidence(crawl: CrawlResult, requirement: Requirement) -> str:
    pages = crawl.html_pages
    page_lines = '\n'.join(f'  {page.url}' for page in pages[:8]) + (f'\n  … and {len(pages) - 8} more' if len(pages) > 8 else '')
    unique = list({(anchor.raw_href, anchor.text): anchor for anchor in crawl.anchors}.values())
    link_lines = '\n'.join(f'  {anchor.describe()}' for anchor in unique[:12]) or '  (no links found)'
    if len(unique) > 12:
        link_lines += f'\n  … and {len(unique) - 12} more'
    return (
        f'Keywords searched: {", ".join(requirement.keywords)}\n'
        f'Pages crawled ({len(pages)}):\n{page_lines}\n'
        f'Links inspected ({len(unique)} unique):\n{link_lines}'
    )


def check_links(crawl: CrawlResult) -> Tuple[List[Finding], List[str], List[str]]:
    """Findings for missing requirements, plus 'name → url' for each found one and the names of missing ones."""
    findings: List[Finding] = []
    found: List[str] = []
    missing: List[str] = []
    for requirement in REQUIREMENTS:
        anchor = _match(requirement, crawl.anchors)
        if anchor:
            found.append(f'{requirement.name} → {anchor.href}')
            continue
        missing.append(requirement.name)
        rule = replace(MISSING_LINK, title=f'No {requirement.name} link found', description=f'{MISSING_LINK.description} {requirement.why}')
        findings.append(
            new_finding(
                MODULE,
                rule,
                severity=requirement.severity,
                location=Location(url=crawl.start_url, element='navigation and footer links'),
                snippet=_links_evidence(crawl, requirement),
                captured=f'{plural(len(crawl.html_pages), "HTML page")} crawled from {crawl.start_url}',
            )
        )
    return findings, found, missing


def check_cookie_consent(crawl: CrawlResult) -> Tuple[Optional[Finding], str]:
    cookies = []
    for page in crawl.pages:
        for raw in page.set_cookies:
            cookies.append(f'  Set-Cookie: {raw.partition("=")[0].strip()}=… (from {page.url})')
    trackers = []
    consent = None
    for page in crawl.html_pages:
        for tag in page.soup.find_all('script', src=True):
            host = urlparse(tag['src']).netloc.lower()
            for domain, label in TRACKERS.items():
                if host == domain or host.endswith('.' + domain):
                    trackers.append(f'  {label}: {page.url} {element_line(tag)}')
        marker = CONSENT_MARKERS.search(page.text)
        if marker and consent is None:
            consent = f'{marker.group(0)} referenced on {page.url}'
    if any('cookie' in _tokens(anchor) or 'cookies' in _tokens(anchor) for anchor in crawl.anchors):
        consent = consent or 'cookie policy link found'

    if not cookies and not trackers:
        return None, 'Cookie consent not assessed as required: no cookies or known trackers were observed.'
    if consent:
        return None, f'Cookie consent mechanism detected ({consent}).'
    evidence = '\n'.join(
        [
            *(['Cookies set:', *cookies[:8]] if cookies else []),
            *(['Trackers loaded:', *trackers[:8]] if trackers else []),
            'Consent managers searched for: Cookiebot, OneTrust, CookieYes, Osano, Termly, iubenda, Didomi, Usercentrics, '
            'Quantcast, Klaro, TrustArc, Complianz, generic cookie-consent/banner markup — none found.',
        ]
    )
    finding = new_finding(
        MODULE,
        COOKIES_WITHOUT_CONSENT,
        location=Location(url=crawl.start_url, element='cookies and third-party scripts'),
        snippet=evidence,
        captured=f'{plural(len(crawl.pages), "response")} and {plural(len(crawl.html_pages), "HTML page")} inspected',
        occurrences=len(cookies) + len(trackers),
    )
    return finding, 'Cookies or trackers were observed without a consent mechanism.'


def run_compliance_analysis(context: 'ScanContext') -> AnalyzerResult:
    crawl = context.crawl()
    findings, found, missing = check_links(crawl)
    unique_links = len({(anchor.raw_href, anchor.text) for anchor in crawl.anchors})
    context.emit(
        MODULE,
        ActivityKind.check,
        f'Searched {plural(unique_links, "unique link")} on {plural(len(crawl.html_pages), "page")} for {len(REQUIREMENTS)} required pages: {len(found)} found',
        '\n'.join(
            [*(f'found    {item}' for item in found), *(f'missing  {name}' for name in missing)]
        ),
    )
    consent_finding, consent_note = check_cookie_consent(crawl)
    if consent_finding:
        findings.append(consent_finding)
    context.emit(MODULE, ActivityKind.check, consent_note, consent_finding.evidence.snippet if consent_finding else None)
    notes = [*(f'Found {item}' for item in found), consent_note]
    if crawl.unchecked:
        notes.append('Some pages were not crawled because of the page limit; links on them were not searched.')
    return AnalyzerResult(
        findings=findings,
        scanned=len(crawl.html_pages),
        scanned_label=f'{plural(len(crawl.html_pages), "page")}, {plural(len(crawl.anchors), "link")}',
        notes=notes,
    )
