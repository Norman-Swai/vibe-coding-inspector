from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Callable, List, Optional, Tuple

from ..schemas import ActivityKind, Finding, Location, ModuleName, Severity, Verification
from .common import AnalyzerResult, Rule, code_only, is_comment_line, new_finding, numbered_lines, plural
from .repo import RepoIndex, SourceFile

if TYPE_CHECKING:
    from ..context import ScanContext

MODULE = ModuleName.static
JS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte'}
PY = {'.py'}
CODE = JS | PY | {'.java', '.go', '.rb', '.php', '.cs', '.kt', '.swift', '.rs', '.c', '.cc', '.cpp', '.h', '.hpp'}

UNRESOLVED_IMPORT = Rule(
    title='Import points to a file that does not exist',
    severity=Severity.high,
    verification=Verification.confirmed,
    check='Every relative import (./ or ../ in JS/TS, from .module in Python) must resolve to a file on disk, '
    'trying the usual extensions and index files.',
    description='The code imports a local module that is not in the repository.',
    impact='The build or the page that loads this module fails at runtime.',
    fix='Restore the missing file or correct the import path (check spelling and letter case).',
)
INTERVAL_WITHOUT_CLEAR = Rule(
    title='setInterval() without a matching clearInterval()',
    severity=Severity.medium,
    verification=Verification.hypothesis,
    check='A file that starts intervals with setInterval() must also call clearInterval() somewhere in that file.',
    description='The file starts repeating timers but never stops any of them.',
    impact='Timers keep running after the component or page that owns them is gone, leaking memory and CPU.',
    fix='Keep the interval id and call clearInterval(id) in the matching cleanup (for example the useEffect return).',
    cwe='CWE-401',
)
LISTENER_WITHOUT_REMOVE = Rule(
    title='Event listeners are added but never removed',
    severity=Severity.low,
    verification=Verification.hypothesis,
    check='In a file, addEventListener() calls without { once } or an AbortSignal must be matched by at least as many removeEventListener() calls.',
    description='The file registers more event listeners than it removes.',
    impact='Listeners on long-lived targets (window, document) pile up each time a component mounts, leaking memory.',
    fix='Remove the listener in the cleanup path, or register it with { once: true } or an AbortController signal.',
    cwe='CWE-401',
)
DEBUGGER_STATEMENT = Rule(
    title='debugger statement left in code',
    severity=Severity.low,
    verification=Verification.confirmed,
    check='JavaScript/TypeScript source must not contain debugger statements.',
    description='A debugger statement pauses execution whenever developer tools are open.',
    impact='Pages freeze for anyone with dev tools open, and it signals unfinished debugging code.',
    fix='Delete the debugger statement.',
)
TODO_MARKERS = Rule(
    title='Unresolved TODO / FIXME markers',
    severity=Severity.info,
    verification=Verification.confirmed,
    check='Comments containing TODO, FIXME, HACK or XXX are listed.',
    description='The file contains notes about unfinished or known-broken code.',
    impact='Unfinished work can hide missing validation, cleanup or error handling.',
    fix='Resolve each note or move it to the issue tracker.',
)

_JS_IMPORT = re.compile(
    r'''(?:\bimport\s+(?:type\s+)?(?:[\w*$\s{},]+?\s+from\s+)?|\bexport\s+(?:type\s+)?(?:\*(?:\s+as\s+\w+)?|\{[^}]*\})\s+from\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)(['"])(\.{1,2}/[^'"\n]+)\1'''
)
_PY_RELATIVE_IMPORT = re.compile(r'^[ \t]*from[ \t]+(\.+)([\w.]+)[ \t]+import\b', re.M)
_JS_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts', '.d.ts', '.json', '.vue', '.svelte']
_INTERVAL = re.compile(r'\bsetInterval\s*\(')
_ADD_LISTENER = re.compile(r'\.addEventListener\s*\(')
_REMOVE_LISTENER = re.compile(r'\.removeEventListener\s*\(')
_DEBUGGER = re.compile(r'^\s*debugger\s*;?\s*(?://.*)?$')
_TODO = re.compile(r'(?:^|\s)(?://|#|/\*|<!--|\*)(?:.*?\W)?(TODO|FIXME|HACK|XXX)\b')


def _lines_matching(source: SourceFile, pattern: re.Pattern, code: bool = True, keep: Optional[Callable[[str], bool]] = None) -> List[int]:
    """Line numbers matching ``pattern``. With ``code`` set, comments and string-literal contents are ignored."""
    numbers = []
    for number, line in enumerate(source.lines, start=1):
        if code and is_comment_line(line):
            continue
        if pattern.search(code_only(line) if code else line) and (keep is None or keep(line)):
            numbers.append(number)
    return numbers


def _file_finding(rule: Rule, source: SourceFile, lines: List[int], extra: str = '') -> Finding:
    return new_finding(
        MODULE,
        rule,
        location=Location(file=source.rel, line_start=lines[0], line_end=lines[-1] if len(lines) > 1 else lines[0]),
        snippet=numbered_lines(source.lines, lines) + (f'\n\n{extra}' if extra else ''),
        captured=f'Static read of {source.rel}',
        occurrences=len(lines),
    )


def _js_candidates(base: Path, spec: str) -> List[Path]:
    spec = spec.split('?', 1)[0].split('#', 1)[0]
    target = base / spec
    candidates = [target, *(target.with_name(target.name + ext) for ext in _JS_EXTENSIONS), *(target / f'index{ext}' for ext in _JS_EXTENSIONS)]
    if target.suffix in {'.js', '.jsx', '.mjs', '.cjs'}:
        # TypeScript ESM imports name the compiled .js file while the source is .ts/.tsx.
        stem = target.with_suffix('')
        candidates.extend(stem.with_name(stem.name + ext) for ext in ('.ts', '.tsx', '.mts', '.cts'))
    return candidates


def _py_candidates(base: Path, dots: str, module: str) -> List[Path]:
    package = base
    for _ in range(len(dots) - 1):
        package = package.parent
    target = package.joinpath(*module.split('.'))
    return [target.with_name(target.name + '.py'), target / '__init__.py', target]


def _unresolved_imports(source: SourceFile) -> Optional[Finding]:
    text = source.text or ''
    base = source.path.parent
    misses: List[Tuple[int, str, List[Path]]] = []
    if source.suffix in JS:
        for match in _JS_IMPORT.finditer(text):
            spec = match.group(2)
            candidates = _js_candidates(base, spec)
            if not any(candidate.is_file() for candidate in candidates):
                misses.append((source.line_of(match.start(2)), spec, candidates))
    elif source.suffix in PY:
        for match in _PY_RELATIVE_IMPORT.finditer(text):
            candidates = _py_candidates(base, match.group(1), match.group(2))
            if not (candidates[0].is_file() or candidates[1].is_file() or candidates[2].is_dir()):
                misses.append((source.line_of(match.start()), match.group(1) + match.group(2), candidates))
    if not misses:
        return None
    root = source.path.parents[len(Path(source.rel).parts) - 1]
    tried = [
        f'{spec} — tried {", ".join(Path(os.path.relpath(os.path.normpath(path), root)).as_posix() for path in candidates[:4])}, …'
        for _, spec, candidates in misses[:5]
    ]
    return _file_finding(UNRESOLVED_IMPORT, source, [line for line, _, _ in misses], 'Not found:\n' + '\n'.join(tried))


def _interval_without_clear(source: SourceFile) -> Optional[Finding]:
    if source.suffix not in JS or 'setInterval' not in (source.text or '') or 'clearInterval' in (source.text or ''):
        return None
    lines = _lines_matching(source, _INTERVAL)
    return _file_finding(INTERVAL_WITHOUT_CLEAR, source, lines, 'clearInterval: not called anywhere in this file') if lines else None


def _listeners_without_remove(source: SourceFile) -> Optional[Finding]:
    if source.suffix not in JS or 'addEventListener' not in (source.text or ''):
        return None
    added = _lines_matching(source, _ADD_LISTENER, keep=lambda line: 'once' not in line and 'signal' not in line)
    removed = _lines_matching(source, _REMOVE_LISTENER)
    if len(added) <= len(removed):
        return None
    return _file_finding(
        LISTENER_WITHOUT_REMOVE, source, added, f'{plural(len(added), "addEventListener call")} vs {plural(len(removed), "removeEventListener call")}'
    )


def _debugger_statements(source: SourceFile) -> Optional[Finding]:
    if source.suffix not in JS or 'debugger' not in (source.text or ''):
        return None
    lines = _lines_matching(source, _DEBUGGER)
    return _file_finding(DEBUGGER_STATEMENT, source, lines) if lines else None


def _todo_markers(source: SourceFile) -> Optional[Finding]:
    lines = _lines_matching(source, _TODO, code=False)
    return _file_finding(TODO_MARKERS, source, lines) if lines else None


CHECKS = [
    (_unresolved_imports, UNRESOLVED_IMPORT),
    (_interval_without_clear, INTERVAL_WITHOUT_CLEAR),
    (_listeners_without_remove, LISTENER_WITHOUT_REMOVE),
    (_debugger_statements, DEBUGGER_STATEMENT),
    (_todo_markers, TODO_MARKERS),
]


def analyse_repo(repo: RepoIndex) -> Tuple[List[Finding], int]:
    findings, scanned, _ = analyse_repo_with_stats(repo)
    return findings, scanned


def analyse_repo_with_stats(repo: RepoIndex) -> Tuple[List[Finding], int, List[str]]:
    """Findings, number of source files read, and one summary line per check for the activity log."""
    findings: List[Finding] = []
    sources = [source for source in repo.with_suffixes(CODE) if source.text is not None]
    per_rule: dict = {rule.title: ([], 0) for _, rule in CHECKS}
    for source in sources:
        for check, rule in CHECKS:
            finding = check(source)
            if finding:
                findings.append(finding)
                files, hits = per_rule[rule.title]
                per_rule[rule.title] = ([*files, source.rel], hits + finding.evidence.occurrences)
    js = [source for source in sources if source.suffix in JS]
    py = [source for source in sources if source.suffix in PY]
    imports = sum(len(_JS_IMPORT.findall(source.text or '')) for source in js) + sum(len(_PY_RELATIVE_IMPORT.findall(source.text or '')) for source in py)
    stats = [f'Files read: {len(sources)} ({len(js)} JS/TS, {len(py)} Python, {len(sources) - len(js) - len(py)} other)', f'Relative imports resolved on disk: {imports}']
    stats += [
        f'{title}: {len(files)} file(s), {hits} occurrence(s)' + (f' — {", ".join(files[:5])}{" …" if len(files) > 5 else ""}' if files else '')
        for title, (files, hits) in per_rule.items()
    ]
    return findings, len(sources), stats


def run_static_analysis(context: 'ScanContext') -> AnalyzerResult:
    repo = context.repo()
    findings, scanned, stats = analyse_repo_with_stats(repo)
    context.emit(MODULE, ActivityKind.check, f'Static checks over {plural(scanned, "source file")}: {plural(len(findings), "finding")}', '\n'.join(stats))
    return AnalyzerResult(
        findings=findings,
        scanned=scanned,
        scanned_label=plural(scanned, 'source file'),
        notes=[
            *repo.notes(),
            'Pattern-based checks: findings marked "hypothesis" need a person to confirm them in context.',
        ],
    )
