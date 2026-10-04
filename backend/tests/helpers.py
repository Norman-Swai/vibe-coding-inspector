from __future__ import annotations

import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from backend.context import ScanContext
from backend.schemas import InspectionMode, ScanOptions, ScanRecord

HeaderValue = Union[str, List[str]]


class FixtureSite:
    """A tiny HTTP server whose routes, headers and status codes are set per test. Counts hits per path."""

    def __init__(self) -> None:
        self.routes: Dict[str, Tuple[int, Dict[str, HeaderValue], str]] = {}
        self.hits: Counter = Counter()
        # Every path requested, in order, so tests can assert what was fetched first.
        self.requests: List[str] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib naming
                site.hits[self.path] += 1
                site.requests.append(self.path)
                status, headers, body = site.routes.get(self.path, (404, {'Content-Type': 'text/html'}, '<html><body>Not found</body></html>'))
                data = body.encode()
                self.send_response(status)
                for name, value in headers.items():
                    for item in value if isinstance(value, list) else [value]:
                        self.send_header(name, item)
                if 'Content-Length' not in headers:
                    self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args) -> None:
                pass

        self._server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self._server.server_address[1]}'
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def add(self, path: str, body: str = '', status: int = 200, headers: Optional[Dict[str, HeaderValue]] = None, content_type: str = 'text/html; charset=utf-8') -> None:
        self.routes[path] = (status, {'Content-Type': content_type, **(headers or {})}, body)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def page(body: str, head: str = '<title>Test</title><meta name="viewport" content="width=device-width">', lang: str = 'en') -> str:
    return f'<!doctype html>\n<html lang="{lang}">\n<head>{head}</head>\n<body>\n{body}\n</body>\n</html>'


def make_context(url: str, repo: Optional[Path] = None, public: bool = False, max_pages: int = 8, timeout: float = 5) -> ScanContext:
    record = ScanRecord(
        id='test',
        target_url=url,
        repo_path=str(repo) if repo else None,
        inspection_mode=InspectionMode.public_readonly if public else InspectionMode.localhost,
        options=ScanOptions(max_pages=max_pages, timeout_seconds=timeout),
        created_at='now',
        modules={},
    )
    return ScanContext(record)


def write_files(root: Path, files: Dict[str, str]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def titles(findings) -> List[str]:
    return [finding.title for finding in findings]
