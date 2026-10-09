from __future__ import annotations

import os
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import List, Optional

from .common import ScanError

# Generated, vendored or tool directories: scanning them is slow and only produces noise.
EXCLUDED_DIRS = {
    '.git', '.hg', '.svn', 'node_modules', 'bower_components', 'vendor', 'dist', 'build', 'out', 'coverage',
    '.next', '.nuxt', '.svelte-kit', '.turbo', '.cache', '.parcel-cache', '.vercel', '.output', 'target',
    '__pycache__', '.venv', 'venv', 'env', '.tox', '.mypy_cache', '.pytest_cache', '.ruff_cache', '.idea', '.vscode',
}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 5_000


@dataclass
class SourceFile:
    path: Path
    rel: str
    size: int

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    @cached_property
    def text(self) -> Optional[str]:
        """File contents, or None for binary/unreadable files. Read once and shared by all modules."""
        try:
            data = self.path.read_bytes()
        except OSError:
            return None
        if b'\x00' in data[:8192]:
            return None
        return data.decode('utf-8', errors='replace')

    @cached_property
    def lines(self) -> List[str]:
        return (self.text or '').splitlines()

    def line_of(self, offset: int) -> int:
        return (self.text or '').count('\n', 0, offset) + 1


class RepoIndex:
    def __init__(self, root: Path) -> None:
        if not root.is_dir():
            raise ScanError(f'Repository path not found: {root}')
        self.root = root
        self.files: List[SourceFile] = []
        self.skipped_large = 0
        self.truncated = False
        for directory, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(name for name in dirnames if name not in EXCLUDED_DIRS)
            for name in sorted(filenames):
                path = Path(directory) / name
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if size > MAX_FILE_BYTES:
                    self.skipped_large += 1
                    continue
                if len(self.files) >= MAX_FILES:
                    self.truncated = True
                    return
                self.files.append(SourceFile(path, path.relative_to(root).as_posix(), size))

    def with_suffixes(self, suffixes: set[str]) -> List[SourceFile]:
        return [item for item in self.files if item.suffix in suffixes and not item.rel.endswith(('.min.js', '.min.css'))]

    def notes(self) -> List[str]:
        notes = ['Excluded generated and vendor directories (node_modules, dist, build, .git, venv, …).']
        if self.skipped_large:
            notes.append(f'Skipped {self.skipped_large} file(s) larger than {MAX_FILE_BYTES // 1_000_000} MB.')
        if self.truncated:
            notes.append(f'Stopped indexing after {MAX_FILES} files; results cover only those files.')
        return notes
