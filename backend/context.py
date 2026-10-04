from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future
from pathlib import Path
from typing import Callable, Dict, List, Optional, TypeVar

from .analyzers.common import ScanError, plural, redact_secrets, truncate
from .analyzers.repo import MAX_FILE_BYTES, RepoIndex
from .analyzers.web import CrawlResult, FetchResult, PageFetcher, crawl, normalize_url
from .schemas import ActivityEvent, ActivityKind, InspectionMode, ModuleName, RequestInfo, ScanRecord

T = TypeVar('T')
EventSink = Callable[[ActivityEvent], None]
MAX_MESSAGE_CHARS = 500
MAX_OUTPUT_CHARS = 4000
MAX_URL_CHARS = 2000
logger = logging.getLogger(__name__)


def _clean(text: Optional[str], limit: int) -> Optional[str]:
    """Bound and mask text that may come from the scanned site before it is stored or shown."""
    if not text:
        return text
    # Truncate generously first so masking stays cheap, mask, then apply the real limit (never cutting a secret in half unmasked).
    return truncate(redact_secrets(text[: limit * 4]), limit)


class ActivityRecorder:
    """Numbers and timestamps every event, then hands it to the sink (the scan store) in order."""

    def __init__(self, sink: Optional[EventSink] = None) -> None:
        self._sink = sink
        self._lock = threading.Lock()
        self._seq = 0
        self._started = time.perf_counter()
        # Without a sink (unit tests, ad-hoc use) events are kept here.
        self.events: List[ActivityEvent] = []

    def emit(
        self,
        module: Optional[ModuleName],
        kind: ActivityKind,
        message: str,
        output: Optional[str] = None,
        request: Optional[RequestInfo] = None,
    ) -> None:
        # Recording activity must never break the scan it describes.
        try:
            if request is not None:
                request = request.model_copy(update={'url': _clean(request.url, MAX_URL_CHARS), 'final_url': _clean(request.final_url, MAX_URL_CHARS)})
            with self._lock:
                self._seq += 1
                event = ActivityEvent(
                    seq=self._seq,
                    at_ms=int((time.perf_counter() - self._started) * 1000),
                    module=module,
                    kind=kind,
                    message=_clean(message, MAX_MESSAGE_CHARS) or '',
                    output=_clean(output, MAX_OUTPUT_CHARS),
                    request=request,
                )
                if self._sink is None:
                    self.events.append(event)
                else:
                    self._sink(event)
        except Exception:  # noqa: BLE001
            logger.exception('Could not record activity event: %.200s', message)


def request_event(result: FetchResult) -> tuple[str, RequestInfo]:
    info = RequestInfo(
        url=result.requested_url,
        final_url=result.url if result.url != result.requested_url else None,
        status=result.status,
        content_type=result.content_type or None,
        bytes=result.size_bytes,
        duration_ms=result.elapsed_ms,
        error=result.error,
    )
    if result.error:
        message = f'GET {result.requested_url} failed: {result.error}'
    else:
        hops = f' → {plural(len(result.redirects), "redirect")} → {result.url}' if result.redirects else ''
        kind = f' {result.content_type}' if result.content_type else ''
        partial = ' (first 2 MB only)' if result.truncated else ''
        message = f'GET {result.requested_url}{hops} -> {result.status} {result.reason}{kind} ({result.elapsed_ms} ms){partial}'
    return message, info


class ScanContext:
    """Everything modules share during one scan. Expensive work (crawl, repo index) runs once, whoever asks first."""

    def __init__(self, record: ScanRecord, sink: Optional[EventSink] = None) -> None:
        self.target_url = normalize_url(record.target_url)
        self.repo_path: Optional[Path] = Path(record.repo_path) if record.repo_path else None
        self.mode = record.inspection_mode
        self.options = record.options
        self.activity = ActivityRecorder(sink)
        self.fetcher = PageFetcher(timeout=record.options.timeout_seconds, on_result=self._log_request)
        self._lock = threading.Lock()
        self._memo: Dict[str, Future] = {}

    @property
    def is_public(self) -> bool:
        return self.mode == InspectionMode.public_readonly

    def emit(self, module: Optional[ModuleName], kind: ActivityKind, message: str, output: Optional[str] = None) -> None:
        self.activity.emit(module, kind, message, output)

    def _log_request(self, result: FetchResult) -> None:
        message, info = request_event(result)
        kind = ActivityKind.request if result.error is None else ActivityKind.warning
        self.activity.emit(None, kind, message, request=info)

    def target_page(self) -> FetchResult:
        page = self.fetcher.get(self.target_url)
        if page.error:
            raise ScanError(f'Could not reach {self.target_url}: {page.error}')
        return page

    def crawl(self) -> CrawlResult:
        return self._once(
            'crawl',
            lambda: crawl(
                self.fetcher,
                self.target_url,
                self.options.max_pages,
                respect_robots=self.is_public,
                emit=lambda kind, message, output=None: self.emit(None, kind, message, output),
            ),
        )

    def repo(self) -> RepoIndex:
        if self.repo_path is None:
            raise ScanError('No repository path was provided.')
        return self._once('repo', self._index_repo)

    def _index_repo(self) -> RepoIndex:
        started = time.perf_counter()
        index = RepoIndex(self.repo_path)
        by_suffix: Dict[str, int] = {}
        for item in index.files:
            by_suffix[item.suffix or '(none)'] = by_suffix.get(item.suffix or '(none)', 0) + 1
        top = ', '.join(f'{suffix} {count}' for suffix, count in sorted(by_suffix.items(), key=lambda pair: -pair[1])[:8])
        skipped = f'; skipped {plural(index.skipped_large, "file")} over {MAX_FILE_BYTES // 1_000_000} MB' if index.skipped_large else ''
        self.emit(
            None,
            ActivityKind.step,
            f'Indexed {plural(len(index.files), "file")} under {self.repo_path} in {int((time.perf_counter() - started) * 1000)} ms{skipped}',
            f'Files by type: {top or "none"}\nExcluded directories: node_modules, dist, build, .git, venv and similar',
        )
        return index

    def close(self) -> None:
        self.fetcher.close()

    def _once(self, key: str, compute: Callable[[], T]) -> T:
        with self._lock:
            future = self._memo.get(key)
            owner = future is None
            if owner:
                future = Future()
                self._memo[key] = future
        if owner:
            try:
                future.set_result(compute())
            except BaseException as exc:  # noqa: BLE001 - re-raised to every caller below
                future.set_exception(exc)
        return future.result()
