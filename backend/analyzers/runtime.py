from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Tuple
from urllib.parse import urlparse

from bs4 import Comment, NavigableString

from ..schemas import Location, ModuleName, Severity, Verification
from .common import AnalyzerResult, Rule, element_line, new_finding, plural, start_tag, truncate
from .web import CrawlResult, FetchResult

if TYPE_CHECKING:
    from bs4 import BeautifulSoup, Tag

    from ..context import ScanContext

MODULE = ModuleName.runtime

BROKEN_LINK = Rule(
    title='Broken link',
    severity=Severity.medium,
    verification=Verification.confirmed,
    check='Every same-origin URL found while crawling was requested; HTTP status 400 or higher, or a failed request, is reported.',
    description='A page or resource that the site links to does not load.',
    impact='Visitors who follow the link reach an error or a dead end, and search engines may drop the page.',
    fix='Fix the route or resource, or update or remove the links that point to it.',
)
MISSING_TITLE = Rule(
    title='Page has no <title>',
    severity=Severity.low,
    verification=Verification.confirmed,
    check='The HTML <head> must contain a non-empty <title> element (WCAG 2.2 SC 2.4.2).',
    description='The page does not declare a title, so tabs, bookmarks and search results fall back to the raw URL.',
    impact='Users and assistive technology cannot tell pages apart.',
    fix='Add a unique, descriptive <title> to every page.',
)
MISSING_LANG = Rule(
    title='<html> element has no lang attribute',
    severity=Severity.low,
    verification=Verification.confirmed,
    check='The root <html> element must declare the page language (WCAG 2.2 SC 3.1.1).',
    description='The page does not declare its language.',
    impact='Screen readers may read the content with the wrong pronunciation rules.',
    fix='Declare the language on the root element, for example <html lang="en">.',
)
MISSING_VIEWPORT = Rule(
    title='Page has no responsive viewport meta tag',
    severity=Severity.low,
    verification=Verification.confirmed,
    check='The <head> must contain <meta name="viewport" content="width=device-width, …">.',
    description='Without a viewport declaration, mobile browsers render the page at desktop width and shrink it.',
    impact='Text is tiny and layouts overflow on phones.',
    fix='Add <meta name="viewport" content="width=device-width, initial-scale=1"> to the <head>.',
)
UNLABELED_CONTROLS = Rule(
    title='Form controls have no accessible label',
    severity=Severity.medium,
    verification=Verification.confirmed,
    check='Each visible input, select and textarea needs a <label for>, a wrapping <label>, aria-label, aria-labelledby or title (WCAG 2.2 SC 1.3.1 and 4.1.2).',
    description='Some form fields have no programmatic label.',
    impact='Screen-reader users cannot tell what to enter, and voice-control users cannot target the field.',
    fix='Give each control a visible <label for="…">, or wrap it in a <label>.',
)
IMAGES_WITHOUT_ALT = Rule(
    title='Images have no alt attribute',
    severity=Severity.low,
    verification=Verification.confirmed,
    check='Every <img> needs an alt attribute; use alt="" for purely decorative images (WCAG 2.2 SC 1.1.1).',
    description='Some images have no text alternative.',
    impact='Screen readers announce the file name instead of the image content.',
    fix='Add a short description in alt, or alt="" if the image is decorative.',
)
ERROR_TEXT = Rule(
    title='Error or stack-trace text is visible on the page',
    severity=Severity.high,
    verification=Verification.hypothesis,
    check='Visible page text is matched against runtime-error signatures: stack traces, "Unhandled exception", "TypeError: …", PHP fatal errors and framework error pages.',
    description='The rendered page contains text that looks like a raw application error.',
    impact='Users see a broken page, and stack traces can leak file paths and implementation details.',
    fix='Fix the failing code path and render a friendly error state; never show stack traces to users.',
    cwe='CWE-209',
)
MIXED_CONTENT = Rule(
    title='HTTPS page loads resources over plain HTTP',
    severity=Severity.medium,
    verification=Verification.confirmed,
    check='On https:// pages, scripts, stylesheets, images, frames, media and form targets must not use http:// URLs.',
    description='The secure page references insecure http:// resources (mixed content).',
    impact='Browsers block or warn about these resources, and they can be modified in transit.',
    fix='Serve the resources over https:// or from the same origin.',
    cwe='CWE-319',
)

ERROR_SIGNATURES = re.compile(
    r'Traceback \(most recent call last\)'
    r'|(?i:\bunhandled (?:exception|rejection|error)\b)'
    r'|\bUncaught (?:\(in promise\) )?\w*(?:Error|Exception)\b'
    r'|\b(?:TypeError|ReferenceError|SyntaxError|RangeError|NullPointerException|AttributeError|KeyError|IndexError): \S'
    r'|Cannot read propert(?:y|ies) of (?:undefined|null)'
    r'|\bundefined is not (?:a function|an object)\b'
    r'|\b(?:Fatal error|Parse error|Warning|Notice): .{1,200}? on line \d+'
    r'|Exception in thread "'
    r'|\bat [\w$.<>]+ \([^()\s]+:\d+:\d+\)'
    r"|Server Error in '/' Application"
    r'|Application error: a (?:client|server)-side exception has occurred'
    r'|(?i:\binternal server error\b)'
)
_NON_VISIBLE = {'script', 'style', 'noscript', 'template'}
_UNLABELLED_EXEMPT_TYPES = {'hidden', 'submit', 'button', 'reset', 'image'}
_MIXED_CONTENT_ATTRS = [
    ('script', 'src'), ('link', 'href'), ('img', 'src'), ('iframe', 'src'), ('audio', 'src'), ('video', 'src'),
    ('source', 'src'), ('embed', 'src'), ('object', 'data'), ('form', 'action'),
]
_AUTH_STATUSES = {401, 403, 407}

# (page url, tag) pairs collected across the crawl, grouped into one finding per rule.
Hits = List[Tuple[str, 'Tag']]


def run_runtime_analysis(context: 'ScanContext') -> AnalyzerResult:
    crawl = context.crawl()
    result = AnalyzerResult(scanned=len(crawl.pages))
    html_pages = crawl.html_pages
    result.scanned_label = f'{plural(len(crawl.pages), "URL")} requested, {plural(len(html_pages), "HTML page")} inspected'

    result.findings.extend(_broken_links(crawl, context.options.timeout_seconds))

    grouped: dict[Rule, Hits] = {rule: [] for rule in (MISSING_TITLE, MISSING_LANG, MISSING_VIEWPORT, UNLABELED_CONTROLS, IMAGES_WITHOUT_ALT, MIXED_CONTENT)}
    for page in html_pages:
        soup = page.soup
        head = soup.head or soup.find('html') or soup
        if not (soup.title and soup.title.get_text(strip=True)):
            grouped[MISSING_TITLE].append((page.url, soup.title or head))
        html = soup.find('html')
        if html is None or not str(html.get('lang', '')).strip():
            grouped[MISSING_LANG].append((page.url, html or head))
        if soup.find('meta', attrs={'name': re.compile(r'^viewport$', re.I)}) is None:
            grouped[MISSING_VIEWPORT].append((page.url, head))
        grouped[UNLABELED_CONTROLS].extend((page.url, tag) for tag in _unlabeled_controls(soup))
        grouped[IMAGES_WITHOUT_ALT].extend(
            (page.url, tag) for tag in soup.find_all('img') if not tag.has_attr('alt') and tag.get('aria-hidden') != 'true'
        )
        if urlparse(page.url).scheme == 'https':
            grouped[MIXED_CONTENT].extend((page.url, tag) for tag in _mixed_content(soup))
        error_finding = _error_text(page)
        if error_finding:
            result.findings.append(error_finding)

    for rule, hits in grouped.items():
        if hits:
            result.findings.append(_grouped_finding(rule, hits, crawl))

    result.notes.extend(_coverage_notes(crawl, context.options.max_pages))
    return result


def _broken_links(crawl: CrawlResult, timeout: float) -> list:
    findings = []
    for page in crawl.pages:
        if page.ok or page.status in _AUTH_STATUSES:
            continue
        path = _short(page.requested_url, crawl)
        referrers = crawl.referrers(page.requested_url)
        is_target = page.requested_url == crawl.start_url
        if page.error:
            title = f'{"Target page" if is_target else "Broken link"}: {path} could not be loaded ({page.error})'
            severity = Severity.medium
        else:
            title = f'{"Target page" if is_target else "Broken link"}: {path} returns HTTP {page.status}'
            severity = Severity.high if page.status >= 500 else Severity.medium
        linked_from = '\n'.join(f'  {_short(ref.page, crawl)} L{ref.line}: {ref.html}' for ref in referrers[:6]) or '  (this is the scan target)'
        if len(referrers) > 6:
            linked_from += f'\n  … and {len(referrers) - 6} more'
        findings.append(
            new_finding(
                MODULE,
                BROKEN_LINK,
                title=title,
                severity=severity,
                location=Location(url=page.requested_url, element=f'linked from {plural(len(referrers), "place")}' if referrers else 'scan target'),
                snippet=f'{page.describe()}\n\nLinked from:\n{linked_from}',
                captured=page.describe(),
                occurrences=max(1, len(referrers)),
            )
        )
    return findings


def _unlabeled_controls(soup: 'BeautifulSoup') -> List['Tag']:
    labelled_ids = {label.get('for') for label in soup.find_all('label') if label.get('for')}
    missing = []
    for control in soup.find_all(['input', 'select', 'textarea']):
        if str(control.get('type', '')).lower() in _UNLABELLED_EXEMPT_TYPES:
            continue
        if any(str(control.get(attr, '')).strip() for attr in ('aria-label', 'aria-labelledby', 'title')):
            continue
        if control.get('id') in labelled_ids or control.find_parent('label') is not None:
            continue
        missing.append(control)
    return missing


def _mixed_content(soup: 'BeautifulSoup') -> List['Tag']:
    hits = []
    for name, attr in _MIXED_CONTENT_ATTRS:
        for tag in soup.find_all(name):
            if str(tag.get(attr, '')).strip().lower().startswith('http://'):
                hits.append(tag)
    return hits


def _error_text(page: FetchResult):
    matches: List[Tuple[int, str]] = []
    for node in page.soup.find_all(string=ERROR_SIGNATURES):
        if type(node) is not NavigableString or isinstance(node, Comment):
            continue
        parent = node.parent
        if parent is None or parent.name in _NON_VISIBLE or any(p.name in _NON_VISIBLE for p in parent.parents):
            continue
        match = ERROR_SIGNATURES.search(node)
        start = max(0, match.start() - 60)
        excerpt = truncate(' '.join(str(node)[start: match.end() + 100].split()), 200)
        matches.append((parent.sourceline, f'L{parent.sourceline} <{parent.name}>: {"…" if start else ""}{excerpt}'))
    if not matches:
        return None
    lines = [text for _, text in matches[:5]] + ([f'… and {len(matches) - 5} more'] if len(matches) > 5 else [])
    return new_finding(
        MODULE,
        ERROR_TEXT,
        location=Location(url=page.url, line_start=matches[0][0], element='visible text'),
        snippet='\n'.join(lines),
        captured=page.describe(),
        occurrences=len(matches),
    )


def _grouped_finding(rule: Rule, hits: Hits, crawl: CrawlResult):
    pages = list(dict.fromkeys(url for url, _ in hits))
    first_url, first_tag = hits[0]
    lines = [f'{_short(url, crawl)} {element_line(tag)}' for url, tag in hits[:10]]
    if len(hits) > 10:
        lines.append(f'… and {len(hits) - 10} more')
    first_page = next(page for page in crawl.pages if page.url == first_url)
    return new_finding(
        MODULE,
        rule,
        location=Location(url=first_url, line_start=getattr(first_tag, 'sourceline', None), element=start_tag(first_tag, 80)),
        snippet='\n'.join(lines),
        captured=f'{plural(len(pages), "page")} affected; first: {first_page.describe()}',
        occurrences=len(hits),
    )


def _coverage_notes(crawl: CrawlResult, max_pages: int) -> List[str]:
    notes = [f'Crawled {plural(len(crawl.pages), "same-origin URL")} (limit {max_pages}) starting at {crawl.start_url}.']
    if crawl.unchecked:
        notes.append(
            f'{plural(len(crawl.unchecked), "more same-origin link")} not requested because the page limit was reached '
            '— raise "Max pages" in Settings to cover them.'
        )
    if crawl.robots_skipped:
        notes.append(f'{plural(len(crawl.robots_skipped), "URL")} skipped because robots.txt disallows them.')
    auth = [page.url for page in crawl.pages if page.status in _AUTH_STATUSES]
    if auth:
        notes.append(f'{plural(len(auth), "URL")} require authentication (401/403) and were not inspected.')
    truncated = [page.url for page in crawl.pages if page.truncated]
    if truncated:
        notes.append(f'{plural(len(truncated), "page")} larger than 2 MB were only partially inspected.')
    notes.append('Passive HTTP + HTML inspection: JavaScript is not executed, so client-rendered content and console errors are not captured.')
    return notes


def _short(url: str, crawl: CrawlResult) -> str:
    parsed = urlparse(url)
    if parsed.netloc == crawl.origin:
        return (parsed.path or '/') + (f'?{parsed.query}' if parsed.query else '')
    return url
