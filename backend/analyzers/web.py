from __future__ import annotations

import codecs
import re
import threading
import time
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import cached_property
from typing import Callable, Dict, List, Optional
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup
from requests.structures import CaseInsensitiveDict

from ..schemas import ActivityKind
from .common import ScanError, plural, start_tag

USER_AGENT = 'VibeCodingInspector/0.2 (+passive inspection)'
MAX_BODY_BYTES = 2_000_000
CRAWL_WORKERS = 4
_TEXT_TYPES = ('text/', 'application/xhtml', 'application/xml', 'application/json', 'application/javascript')


@dataclass
class FetchResult:
    requested_url: str
    url: str
    status: Optional[int] = None
    reason: str = ''
    headers: CaseInsensitiveDict = field(default_factory=CaseInsensitiveDict)
    set_cookies: List[str] = field(default_factory=list)
    redirects: List[str] = field(default_factory=list)
    text: str = ''
    truncated: bool = False
    elapsed_ms: int = 0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and self.status < 400

    @property
    def content_type(self) -> str:
        return self.headers.get('content-type', '').split(';')[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return self.content_type in {'text/html', 'application/xhtml+xml'}

    @cached_property
    def soup(self) -> BeautifulSoup:
        return BeautifulSoup(self.text, 'html.parser')

    def describe(self) -> str:
        """One-line, reproducible description of the request, used as captured output in evidence."""
        chain = ' -> '.join([*self.redirects, self.url]) if self.redirects else self.url
        if self.error:
            return f'GET {chain} failed: {self.error}'
        kind = f' {self.content_type}' if self.content_type else ''
        return f'GET {chain} -> {self.status} {self.reason}{kind} ({self.elapsed_ms} ms)'.replace('  ', ' ')


class PageFetcher:
    """Per-scan HTTP client. Each URL is fetched at most once and shared between modules (single flight)."""

    def __init__(self, timeout: float, on_result: Optional[Callable[['FetchResult'], None]] = None) -> None:
        self.timeout = timeout
        self._on_result = on_result
        self._lock = threading.Lock()
        self._cache: Dict[str, Future] = {}
        self._local = threading.local()
        self._sessions: List[requests.Session] = []
        self.request_count = 0

    def get(self, url: str) -> FetchResult:
        with self._lock:
            future = self._cache.get(url)
            owner = future is None
            if owner:
                future = Future()
                self._cache[url] = future
                self.request_count += 1
        if owner:
            try:
                result = self._fetch(url)
            except BaseException as exc:
                future.set_exception(exc)
                raise
            future.set_result(result)
            if self._on_result is not None:
                self._on_result(result)
            if result.url != url:
                with self._lock:
                    self._cache.setdefault(result.url, future)
        return future.result()

    def close(self) -> None:
        with self._lock:
            sessions, self._sessions = self._sessions, []
        for session in sessions:
            session.close()

    def _session(self) -> requests.Session:
        session = getattr(self._local, 'session', None)
        if session is None:
            session = requests.Session()
            session.headers['User-Agent'] = USER_AGENT
            self._local.session = session
            with self._lock:
                self._sessions.append(session)
        return session

    def _fetch(self, url: str) -> FetchResult:
        started = time.perf_counter()
        try:
            with self._session().get(
                url, timeout=(min(5.0, self.timeout), self.timeout), stream=True, allow_redirects=True
            ) as response:
                result = FetchResult(
                    requested_url=url,
                    url=response.url,
                    status=response.status_code,
                    reason=response.reason or '',
                    headers=response.headers,
                    set_cookies=_set_cookie_headers(response),
                    redirects=[item.url for item in response.history],
                )
                if not result.content_type or result.content_type.startswith(_TEXT_TYPES):
                    body = bytearray()
                    for chunk in response.iter_content(65536):
                        body.extend(chunk)
                        if len(body) >= MAX_BODY_BYTES:
                            result.truncated = True
                            break
                    result.text = bytes(body).decode(_charset(response.headers.get('content-type', '')), errors='replace')
        except requests.RequestException as exc:
            result = FetchResult(requested_url=url, url=url, error=describe_request_error(exc, self.timeout))
        result.elapsed_ms = int((time.perf_counter() - started) * 1000)
        return result


def _charset(content_type: str) -> str:
    match = re.search(r'charset=["\']?([\w.-]+)', content_type, flags=re.I)
    if match:
        try:
            return codecs.lookup(match.group(1)).name
        except LookupError:
            pass
    return 'utf-8'


def _set_cookie_headers(response: requests.Response) -> List[str]:
    cookies: List[str] = []
    for item in [*response.history, response]:
        try:
            cookies.extend(item.raw.headers.getlist('Set-Cookie'))
        except AttributeError:
            header = item.headers.get('set-cookie')
            if header:
                cookies.append(header)
    return cookies


def describe_request_error(exc: requests.RequestException, timeout: float) -> str:
    text = str(exc)
    if isinstance(exc, requests.Timeout):
        return f'timed out after {timeout:g}s'
    if isinstance(exc, requests.exceptions.SSLError):
        return 'TLS/SSL handshake failed'
    if isinstance(exc, requests.TooManyRedirects):
        return 'too many redirects'
    if isinstance(exc, (requests.exceptions.InvalidURL, requests.exceptions.MissingSchema)):
        return 'invalid URL'
    if isinstance(exc, requests.ConnectionError):
        if 'refused' in text.lower():
            return 'connection refused (is the app running?)'
        if any(marker in text for marker in ('Name or service not known', 'nodename nor servname', 'getaddrinfo failed', 'Temporary failure in name resolution')):
            return 'host name could not be resolved'
        return 'connection failed'
    return type(exc).__name__


def normalize_url(url: str) -> str:
    return urldefrag(url.strip()).url


@dataclass
class Anchor:
    page: str
    href: str
    raw_href: str
    text: str
    line: Optional[int]
    html: str

    def describe(self) -> str:
        return f'{self.page} L{self.line}: {self.html}' if self.line else f'{self.page}: {self.html}'


@dataclass
class CrawlResult:
    start_url: str
    origin: str
    pages: List[FetchResult]
    anchors: List[Anchor]
    unchecked: List[str]
    robots_skipped: List[str]

    @property
    def html_pages(self) -> List[FetchResult]:
        return [page for page in self.pages if page.ok and page.is_html and urlparse(page.url).netloc == self.origin]

    @cached_property
    def _referrers(self) -> Dict[str, List[Anchor]]:
        by_href: Dict[str, List[Anchor]] = defaultdict(list)
        for anchor in self.anchors:
            by_href[anchor.href].append(anchor)
        return by_href

    def referrers(self, url: str) -> List[Anchor]:
        return self._referrers.get(url, [])


Emit = Callable[..., None]


def _no_emit(kind: ActivityKind, message: str, output: Optional[str] = None) -> None:
    pass


def crawl(fetcher: PageFetcher, start_url: str, max_pages: int, respect_robots: bool, emit: Emit = _no_emit) -> CrawlResult:
    """Breadth-first, same-origin crawl. Each level is fetched concurrently; at most ``max_pages`` URLs are requested."""
    start = normalize_url(start_url)
    emit(ActivityKind.step, f'Crawl started at {start} (limit {max_pages} URLs{", respecting robots.txt" if respect_robots else ""})')
    first = fetcher.get(start)
    if first.error:
        emit(ActivityKind.error, f'Target unreachable: {first.error}')
        raise ScanError(f'Could not reach {start}: {first.error}')

    origin = urlparse(first.url).netloc
    seen = {start, normalize_url(first.url)}
    pages: List[FetchResult] = [first]
    anchors: List[Anchor] = []
    unchecked: List[str] = []
    robots_skipped: List[str] = []
    robots = _load_robots(fetcher, first.url, emit) if respect_robots else None

    def collect(page: FetchResult) -> List[str]:
        if not (page.ok and page.is_html and urlparse(page.url).netloc == origin):
            return []
        discovered: List[str] = []
        anchors_before = len(anchors)
        for tag in page.soup.find_all('a', href=True):
            raw = tag['href'].strip()
            if not raw or raw.startswith('#'):
                continue
            absolute = urljoin(page.url, raw)
            parsed = urlparse(absolute)
            web = parsed.scheme in {'http', 'https'}
            if web:
                absolute = normalize_url(absolute)
            anchors.append(Anchor(page.url, absolute, raw, tag.get_text(' ', strip=True), tag.sourceline, start_tag(tag)))
            if not web or parsed.netloc != origin or absolute in seen:
                continue
            seen.add(absolute)
            if robots is not None and not robots.can_fetch(USER_AGENT, absolute):
                robots_skipped.append(absolute)
            else:
                discovered.append(absolute)
        found = len(anchors) - anchors_before
        emit(
            ActivityKind.step,
            f'Parsed {urlparse(page.url).path or "/"}: {plural(found, "link")}, {len(discovered)} new same-origin URL{"" if len(discovered) == 1 else "s"} queued',
            '\n'.join(discovered[:20]) + (f'\n… and {len(discovered) - 20} more' if len(discovered) > 20 else '') if discovered else None,
        )
        return discovered

    frontier = collect(first)
    with ThreadPoolExecutor(max_workers=CRAWL_WORKERS, thread_name_prefix='crawl') as pool:
        while frontier:
            room = max_pages - len(pages)
            if room <= 0:
                unchecked.extend(frontier)
                break
            batch, rest = frontier[:room], frontier[room:]
            unchecked.extend(rest)
            frontier = []
            for page in pool.map(fetcher.get, batch):
                pages.append(page)
                frontier.extend(collect(page))

    if unchecked:
        emit(ActivityKind.warning, f'Page limit of {max_pages} reached: {plural(len(unchecked), "same-origin URL")} not requested', '\n'.join(unchecked[:30]))
    if robots_skipped:
        emit(ActivityKind.warning, f'robots.txt disallows {plural(len(robots_skipped), "URL")}; not requested', '\n'.join(robots_skipped[:30]))
    html = sum(1 for page in pages if page.ok and page.is_html)
    failed = sum(1 for page in pages if not page.ok)
    emit(ActivityKind.result, f'Crawl finished: {plural(len(pages), "URL")} requested, {plural(html, "HTML page")}, {failed} failed')
    return CrawlResult(start, origin, pages, anchors, unchecked, robots_skipped)


def _load_robots(fetcher: PageFetcher, base_url: str, emit: Emit = _no_emit) -> Optional[RobotFileParser]:
    result = fetcher.get(urljoin(base_url, '/robots.txt'))
    if not result.ok or not result.text:
        emit(ActivityKind.check, f'robots.txt not found ({result.status or result.error}); all paths allowed')
        return None
    parser = RobotFileParser()
    lines = result.text.splitlines()
    parser.parse(lines)
    rules = [line.strip() for line in lines if line.strip().lower().startswith(('disallow', 'allow', 'user-agent'))]
    emit(ActivityKind.check, f'robots.txt loaded: {plural(len(rules), "rule")}', '\n'.join(rules[:40]))
    return parser
