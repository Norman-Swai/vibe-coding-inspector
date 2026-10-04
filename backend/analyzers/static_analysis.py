from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Iterable, List

from ..schemas import Evidence, Finding, Location, ModuleName, ScanRecord, Severity, Verification


PATTERNS = [
    (
        'Possible uncleared timer or interval',
        re.compile(r'setInterval\(|setTimeout\(', re.I),
        Severity.medium,
        'Review component teardown or cleanup logic for timer lifecycle management.',
    ),
    (
        'Potential event-listener cleanup gap',
        re.compile(r'addEventListener\(', re.I),
        Severity.medium,
        'Confirm listeners are removed during component or process teardown.',
    ),
    (
        'Potential architectural TODO or placeholder',
        re.compile(r'TODO|FIXME|HACK', re.I),
        Severity.low,
        'Replace placeholder implementation notes with resolved code or tracked issues.',
    ),
]


def run_static_analysis(record: ScanRecord) -> List[Finding]:
    repo_path = Path(record.repo_path or '')
    if not repo_path.is_dir():
        raise ValueError(f'Repository path not found: {repo_path}')

    findings: List[Finding] = []
    for file_path in _iter_source_files(repo_path):
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for title, pattern, severity, remediation in PATTERNS:
            match = pattern.search(content)
            if match:
                line_no = content[: match.start()].count('\n') + 1
                snippet = '\n'.join(content.splitlines()[max(0, line_no - 1): line_no + 2])[:400]
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title=title,
                        category=ModuleName.static,
                        severity=severity,
                        verification=Verification.hypothesis,
                        source_modules=[ModuleName.static],
                        location=Location(file=str(file_path), line_start=line_no, line_end=line_no + 2),
                        evidence=Evidence(snippet=snippet, captured_output='Regex-based static inspection'),
                        description_plain='A source pattern matched a maintainability or lifecycle-risk heuristic.',
                        impact_plain='Unchecked lifecycle or placeholder patterns can degrade reliability over time.',
                        fix_suggestion={"summary": remediation},
                    )
                )
    return findings


def _iter_source_files(repo_path: Path) -> Iterable[Path]:
    suffixes = {'.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.go', '.rb', '.php'}
    for path in repo_path.rglob('*'):
        if path.is_file() and path.suffix in suffixes and '.git' not in path.parts and 'node_modules' not in path.parts:
            yield path
