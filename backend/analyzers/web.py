from __future__ import annotations

import codecs
import logging
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
from requests.utils import requote_uri
from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url

from ..schemas import ActivityKind
from .common import ScanError, plural, start_tag

logger = logging.getLogger(__name__)

USER_AGENT = 'VibeCodingInspector/0.2 (+passive inspection)'
MAX_BODY_BYTES = 2_000_000
MAX_REDIRECTS = 10
CRAWL_WORKERS = 4
LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'}
_TEXT_TYPES = ('text/', 'application/xhtml', 'application/xml', 'application/json', 'application/javascript')


def url_host(url: str) -> Optional[str]:
    """The host the HTTP client will connect to, or None when it cannot parse the URL.

    requests hands URLs to urllib3, whose parser reads backslashes, userinfo and ports differently from urllib.parse,
    so every host decision must use it rather than urlparse().hostname.
    """
    try:
        host = parse_url(url).host
    except LocationParseError:
        return None
    # urllib3 lowercases the host and keeps the brackets around an IPv6 address.
    return host.strip('[]') if host else None


def is_local(url: str) -> bool:
    return url_host(url) in LOCAL_HOSTS


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
    # Bytes actually received (text bodies) or the declared Content-Length (other types); None if unknown.
    size_bytes: Optional[int] = None
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

    def __init__(self, timeout: float, on_result: Optional[Callable[['FetchResult'], None]] = None, local_only: bool = False) -> None:
        self.timeout = timeout
        self._on_result = on_result
        # Localhost mode must never contact another host, so a redirect away from a local host is refused, not followed.
        self.local_only = local_only
        self._lock = threading.Lock()
        self._cache: Dict[str, Future] = {}
        self._local = threading.local()
        self._sessions: List[requests.Session] = []
        self.request_count = 0

    def get(self, url: str, notify: bool = True) -> FetchResult:
        """Fetch ``url`` (once per scan). With ``notify=False`` the caller records the request itself."""
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
            if notify and self._on_result is not None:
                # Observers (the activity log) must never be able to break fetching or the analysis that depends on it.
                try:
                    self._on_result(result)
                except Exception:  # noqa: BLE001
                    logger.exception('Request observer failed for %s', url)
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
        # Redirect responses already received, in order (what requests exposes as response.history).
        hops: List[requests.Response] = []
        try:
            response = self._send(url)
            try:
                # Redirects are followed by hand so that a hop to a forbidden host is refused before anything is sent to it.
                while True:
                    target = self._redirect_target(response)
                    if target is None:
                        result = self._read(url, response, hops)
                        break
                    hops.append(response)
                    if len(hops) > MAX_REDIRECTS:
                        raise requests.TooManyRedirects(f'Exceeded {MAX_REDIRECTS} redirects.')
                    if self.local_only and not is_local(target):
                        result = FetchResult(
                            requested_url=url,
                            url=response.url,
                            set_cookies=_set_cookie_headers(hops),
                            redirects=[hop.url for hop in hops[:-1]],
                            error=f'redirect to {url_host(target) or target} blocked: localhost mode only contacts local hosts',
                        )
                        break
                    response = self._send(target)
            finally:
                for item in [*hops, response]:
                    item.close()
        except requests.RequestException as exc:
            result = FetchResult(requested_url=url, url=url, error=describe_request_error(exc, self.timeout))
        result.elapsed_ms = int((time.perf_counter() - started) * 1000)
        return result

    def _send(self, url: str) -> requests.Response:
        return self._session().get(url, timeout=(min(5.0, self.timeout), self.timeout), stream=True, allow_redirects=False)

    def _redirect_target(self, response: requests.Response) -> Optional[str]:
        """The absolute URL a redirect response points to, resolved the way requests resolves it; None otherwise."""
        location = self._session().get_redirect_target(response)
        return requote_uri(urljoin(response.url, location)) if location is not None else None

    @staticmethod
    def _read(url: str, response: requests.Response, hops: List[requests.Response]) -> FetchResult:
        result = FetchResult(
            requested_url=url,
            url=response.url,
            status=response.status_code,
            reason=response.reason or '',
            headers=response.headers,
            set_cookies=_set_cookie_headers([*hops, response]),
            redirects=[hop.url for hop in hops],
        )
        if not result.content_type or result.content_type.startswith(_TEXT_TYPES):
            body = bytearray()
            for chunk in response.iter_content(65536):
                body.extend(chunk)
                if len(body) >= MAX_BODY_BYTES:
                    result.truncated = True
                    break
            result.size_bytes = len(body)
            result.text = _decode(bytes(body), response.headers.get('content-type', ''))
        else:
            declared = response.headers.get('content-length', '')
            result.size_bytes = int(declared) if re.fullmatch(r'[0-9]{1,15}', declared) else None
        return result


def _decode(body: bytes, content_type: str) -> str:
    try:
        text = body.decode(_charset(content_type), errors='replace')
    except Exception:  # noqa: BLE001 - exotic codecs named by the server; fall back to UTF-8
        text = body.decode('utf-8', errors='replace')
    # Codecs such as utf-7 can produce lone surrogates, which cannot be re-encoded or serialised to JSON.
    return text.encode('utf-8', errors='replace').decode('utf-8')


def _charset(content_type: str) -> str:
    match = re.search(r'charset=["\']?([\w.-]+)', content_type, flags=re.I)
    if match:
        try:
            return codecs.lookup(match.group(1)).name
        except LookupError:
            pass
    return 'utf-8'


def _set_cookie_headers(responses: List[requests.Response]) -> List[str]:
    """Every Set-Cookie header received along the redirect chain."""
    cookies: List[str] = []
    for item in responses:
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


# (kind, message, output, request): ``request`` is the FetchResult an event describes, for lookups logged as checks.
Emit = Callable[..., None]


def _no_emit(kind: ActivityKind, message: str, output: Optional[str] = None, request: Optional[FetchResult] = None) -> None:
    pass


@dataclass
class Robots:
    """The robots.txt rules of one origin. ``parser`` is None when the file was not found, which allows every path."""

    origin: str
    parser: Optional[RobotFileParser] = None

    def allows(self, url: str) -> bool:
        return self.parser is None or self.parser.can_fetch(USER_AGENT, url)


def require_allowed(robots: Optional[Robots], url: str) -> None:
    """Public read-only mode never requests a URL that robots.txt disallows, not even the start URL."""
    if robots is not None and not robots.allows(url):
        raise ScanError(f'robots.txt disallows {url}; public read-only mode does not fetch it')


def crawl(fetcher: PageFetcher, start_url: str, max_pages: int, robots: Optional[Robots] = None, emit: Emit = _no_emit) -> CrawlResult:
    """Breadth-first, same-origin crawl. Each level is fetched concurrently; at most ``max_pages`` URLs are requested.

    ``robots`` (public mode) must already hold the rules of the start URL's origin, so nothing is requested before they are read.
    """
    start = normalize_url(start_url)
    emit(ActivityKind.step, f'Crawl started at {start} (limit {max_pages} URLs{", respecting robots.txt" if robots is not None else ""})')
    require_allowed(robots, start)
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
    if robots is not None and origin != robots.origin:
        # The target redirected to another origin, whose own robots.txt governs the rest of the crawl.
        robots = load_robots(fetcher, first.url, emit)

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
            if robots is not None and not robots.allows(absolute):
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


def load_robots(fetcher: PageFetcher, base_url: str, emit: Emit = _no_emit) -> Robots:
    """Fetch and parse robots.txt of ``base_url``'s origin. A missing file is expected, so the lookup is logged as a check
    carrying the request rather than as a failed page request."""
    robots = Robots(origin=urlparse(base_url).netloc)
    result = fetcher.get(urljoin(base_url, '/robots.txt'), notify=False)
    if not result.ok or not result.text:
        emit(ActivityKind.check, f'robots.txt not found ({result.status or result.error}); all paths allowed', None, result)
        return robots
    robots.parser = RobotFileParser()
    lines = result.text.splitlines()
    robots.parser.parse(lines)
    rules = [line.strip() for line in lines if line.strip().lower().startswith(('disallow', 'allow', 'user-agent'))]
    emit(ActivityKind.check, f'robots.txt loaded: {plural(len(rules), "rule")}', '\n'.join(rules[:40]), result)
    return robots
