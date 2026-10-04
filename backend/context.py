from __future__ import annotations

import threading
from concurrent.futures import Future
from pathlib import Path
from typing import Callable, Dict, Optional, TypeVar

from .analyzers.common import ScanError
from .analyzers.repo import RepoIndex
from .analyzers.web import CrawlResult, FetchResult, PageFetcher, crawl, normalize_url
from .schemas import InspectionMode, ScanRecord

T = TypeVar('T')


class ScanContext:
    """Everything modules share during one scan. Expensive work (crawl, repo index) runs once, whoever asks first."""

    def __init__(self, record: ScanRecord) -> None:
        self.target_url = normalize_url(record.target_url)
        self.repo_path: Optional[Path] = Path(record.repo_path) if record.repo_path else None
        self.mode = record.inspection_mode
        self.options = record.options
        self.fetcher = PageFetcher(timeout=record.options.timeout_seconds)
        self._lock = threading.Lock()
        self._memo: Dict[str, Future] = {}

    @property
    def is_public(self) -> bool:
        return self.mode == InspectionMode.public_readonly

    def target_page(self) -> FetchResult:
        page = self.fetcher.get(self.target_url)
        if page.error:
            raise ScanError(f'Could not reach {self.target_url}: {page.error}')
        return page

    def crawl(self) -> CrawlResult:
        return self._once(
            'crawl', lambda: crawl(self.fetcher, self.target_url, self.options.max_pages, respect_robots=self.is_public)
        )

    def repo(self) -> RepoIndex:
        if self.repo_path is None:
            raise ScanError('No repository path was provided.')
        return self._once('repo', lambda: RepoIndex(self.repo_path))

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
