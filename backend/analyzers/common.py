from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterable, List, Optional, Sequence

from ..schemas import Evidence, Finding, FixSuggestion, Location, ModuleName, Severity, Verification

if TYPE_CHECKING:
    from bs4 import Tag


class ScanError(Exception):
    """A module could not complete. The message is shown to the user as the module's failure reason."""


@dataclass
class AnalyzerResult:
    findings: List[Finding] = field(default_factory=list)
    scanned: int = 0
    scanned_label: str = ''
    notes: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Rule:
    """Static description of a check. Analyzers pair a rule with what they observed to build a finding."""

    title: str
    severity: Severity
    verification: Verification
    check: str
    description: str
    impact: str
    fix: str
    cwe: Optional[str] = None
    category: Optional[ModuleName] = None


def new_finding(
    module: ModuleName,
    rule: Rule,
    *,
    location: Location,
    snippet: str,
    captured: str,
    title: Optional[str] = None,
    severity: Optional[Severity] = None,
    occurrences: int = 1,
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        title=title or rule.title,
        category=rule.category or module,
        severity=severity or rule.severity,
        verification=rule.verification,
        source_modules=[module],
        location=location,
        evidence=Evidence(snippet=snippet, captured_output=captured, check=rule.check, occurrences=occurrences),
        description_plain=rule.description,
        impact_plain=rule.impact,
        cwe_id=rule.cwe,
        fix_suggestion=FixSuggestion(summary=rule.fix),
    )


def truncate(text: str, limit: int) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + '…'


def mask_secret(value: str) -> str:
    """Keep just enough of a secret to recognise it; never enough to use it."""
    if len(value) <= 8:
        return '•' * 8
    return f'{value[:3]}{"•" * 6} [{len(value)} chars]'


def numbered_excerpt(lines: Sequence[str], line_no: int, context: int = 1, width: int = 160) -> str:
    """Source lines around ``line_no`` (1-based) with the matching line marked by '>'."""
    start = max(1, line_no - context)
    end = min(len(lines), line_no + context)
    pad = len(str(end))
    out = []
    for number in range(start, end + 1):
        marker = '>' if number == line_no else ' '
        out.append(f'{marker} {number:>{pad}} | {truncate(lines[number - 1], width) if lines[number - 1].strip() else ""}')
    return '\n'.join(out)


def numbered_lines(lines: Sequence[str], line_numbers: Iterable[int], limit: int = 8, width: int = 160) -> str:
    """One line per occurrence, e.g. 'L12: setInterval(tick, 1000);'."""
    numbers = list(line_numbers)
    out = [f'L{number}: {truncate(lines[number - 1], width)}' for number in numbers[:limit]]
    if len(numbers) > limit:
        out.append(f'… and {len(numbers) - limit} more')
    return '\n'.join(out)


def start_tag(tag: 'Tag', limit: int = 180) -> str:
    """Render only the opening tag (plus link text for anchors) instead of the whole subtree."""
    attrs = []
    for name, value in tag.attrs.items():
        if isinstance(value, list):
            value = ' '.join(value)
        attrs.append(f'{name}="{value}"' if value != '' else name)
    rendered = f'<{tag.name}{" " + " ".join(attrs) if attrs else ""}>'
    if tag.name in {'a', 'button', 'label', 'title'}:
        rendered += f'{truncate(tag.get_text(" ", strip=True), 60)}</{tag.name}>'
    return truncate(rendered, limit)


def element_line(tag: 'Tag') -> str:
    line = getattr(tag, 'sourceline', None)
    return f'L{line}: {start_tag(tag)}' if line else start_tag(tag)


def element_lines(tags: Sequence['Tag'], limit: int = 8) -> str:
    out = [element_line(tag) for tag in tags[:limit]]
    if len(tags) > limit:
        out.append(f'… and {len(tags) - limit} more')
    return '\n'.join(out)


_STRING_LITERAL = re.compile(r'''(["'`])(?:\\.|(?!\1).)*\1''')
_TRAILING_COMMENT = re.compile(r'(?:^|\s)(?://|#).*$')


def is_comment_line(line: str) -> bool:
    return line.lstrip().startswith(('//', '#', '*', '/*', '<!--'))


def code_only(line: str) -> str:
    """The line with string-literal contents and trailing comments removed, so code patterns only match real code."""
    return _TRAILING_COMMENT.sub('', _STRING_LITERAL.sub(r'\1\1', line))


def plural(count: int, word: str, plural_word: Optional[str] = None) -> str:
    return f'{count} {word if count == 1 else plural_word or word + "s"}'
