from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..schemas import ActivityKind, Finding, Location, ModuleName, Severity, Verification
from .common import AUTH_STATUSES, AnalyzerResult, Rule, element_line, new_finding, plural
from .web import Anchor, CrawlResult, FetchResult

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
BROKEN_LINK = Rule(
    title='Required link is broken',
    severity=Severity.medium,
    verification=Verification.confirmed,
    check='The matched link was requested during the crawl; HTTP status 400 or higher, or a failed request, is reported.',
    description='A link to this page exists, but the page does not load.',
    impact='Visitors who follow the link reach an error instead of the information, so the requirement is not met in practice.',
    fix='Fix the route or update the link so that the page loads.',
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


def _matches(requirement: Requirement, anchor: Anchor) -> bool:
    tokens = _tokens(anchor)
    return any(keyword in tokens or (len(keyword) > 5 and keyword in ' '.join(tokens)) for keyword in requirement.keywords)


def _match(requirement: Requirement, crawl: CrawlResult, pages: Dict[str, FetchResult]) -> Tuple[Optional[Anchor], Optional[FetchResult]]:
    """The first matching link and the crawl's response for its target, if it was requested. A link that loaded is preferred."""
    matches = [(anchor, pages.get(anchor.href)) for anchor in crawl.anchors if _matches(requirement, anchor)]
    return next((match for match in matches if match[1] is not None and match[1].ok), matches[0] if matches else (None, None))


def _not_verified(crawl: CrawlResult, anchor: Anchor) -> str:
    """Why the crawl did not request the link target."""
    parsed = urlparse(anchor.href)
    if parsed.scheme not in {'http', 'https'}:
        return f'{parsed.scheme}: link'
    if parsed.netloc != crawl.origin:
        return 'off-site'
    if anchor.href in crawl.robots_skipped:
        return 'robots.txt disallows it'
    if anchor.href in crawl.unchecked:
        return 'page limit reached'
    return 'not requested'


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


def check_links(crawl: CrawlResult) -> Tuple[List[Finding], List[str], List[str], List[str]]:
    """Findings for missing and broken requirements, plus 'name → url (…)' for found and broken ones and the names of missing ones.

    A match is verified against the crawl: a link whose target loaded is found, one whose target failed is broken, and one
    the crawl did not request (off-site, robots.txt, page limit) or that requires authentication is found but marked as not verified.
    """
    findings: List[Finding] = []
    found: List[str] = []
    broken: List[str] = []
    missing: List[str] = []
    pages = {page.requested_url: page for page in crawl.pages}
    for page in crawl.pages:
        pages.setdefault(page.url, page)
    for requirement in REQUIREMENTS:
        anchor, page = _match(requirement, crawl, pages)
        if anchor and (page is None or page.status in AUTH_STATUSES):
            # Like the runtime module, a 401/403 is "not for anonymous visitors", not a broken page.
            why = _not_verified(crawl, anchor) if page is None else f'requires authentication, HTTP {page.status}'
            found.append(f'{requirement.name} → {anchor.href} (not verified: {why})')
            continue
        if anchor and page.ok:
            found.append(f'{requirement.name} → {anchor.href} (verified, HTTP {page.status})')
            continue
        if anchor:
            status = f'HTTP {page.status}' if page.status else page.error
            broken.append(f'{requirement.name} → {anchor.href} ({status})')
            findings.append(
                new_finding(
                    MODULE,
                    BROKEN_LINK,
                    title=f'{requirement.name.capitalize()} link is broken ({status})',
                    severity=requirement.severity,
                    location=Location(url=anchor.page, line_start=anchor.line, element=anchor.html),
                    snippet=f'{anchor.describe()}\n{page.describe()}',
                    captured=page.describe(),
                )
            )
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
    return findings, found, broken, missing


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
    findings, found, broken, missing = check_links(crawl)
    unique_links = len({(anchor.raw_href, anchor.text) for anchor in crawl.anchors})
    context.emit(
        MODULE,
        ActivityKind.check,
        f'Searched {plural(unique_links, "unique link")} on {plural(len(crawl.html_pages), "page")} for {len(REQUIREMENTS)} required pages: '
        f'{len(found)} found, {len(broken)} broken, {len(missing)} missing',
        '\n'.join(
            [*(f'found    {item}' for item in found), *(f'broken   {item}' for item in broken), *(f'missing  {name}' for name in missing)]
        ),
    )
    consent_finding, consent_note = check_cookie_consent(crawl)
    if consent_finding:
        findings.append(consent_finding)
    context.emit(MODULE, ActivityKind.check, consent_note, consent_finding.evidence.snippet if consent_finding else None)
    notes = [*(f'Found {item}' for item in found), *(f'Broken link: {item}' for item in broken), consent_note]
    if crawl.unchecked:
        notes.append('Some pages were not crawled because of the page limit; links on them were not searched.')
    return AnalyzerResult(
        findings=findings,
        scanned=len(crawl.html_pages),
        scanned_label=f'{plural(len(crawl.html_pages), "page")}, {plural(len(crawl.anchors), "link")}',
        notes=notes,
    )
