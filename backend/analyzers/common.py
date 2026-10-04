from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Callable, Iterable, List, Optional, Pattern, Sequence, Tuple

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
    # Raw secret values the module found, so the orchestrator can mask them wherever any module quotes them. Never stored.
    secrets: List[str] = field(default_factory=list)


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
    finding = Finding(
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
    # Whatever a module quotes from the site or the code is masked here, so no analyzer can forget to.
    return redact_finding(finding)


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


# Credential formats with a distinctive shape. Used by the secret scanner and to mask anything the inspector records.
# Responses that mean "not for anonymous visitors" rather than "broken": the page exists but was not inspected.
AUTH_STATUSES = {401, 403, 407}

CREDENTIAL_FORMATS: List[Tuple[str, Pattern[str]]] = [
    ('AWS access key ID', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b')),
    ('Private key', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----')),
    ('GitHub token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b')),
    ('Slack token', re.compile(r'\bxox[abposr]-[A-Za-z0-9-]{10,}')),
    ('Stripe live key', re.compile(r'\b[rs]k_live_[A-Za-z0-9]{20,}')),
    ('Anthropic API key', re.compile(r'\bsk-ant-[A-Za-z0-9_-]{20,}')),
    ('OpenAI API key', re.compile(r'\bsk-(?:proj-)?(?!ant-)[A-Za-z0-9_-]{32,}')),
    ('Google API key', re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')),
]
# Values of URL query parameters whose names suggest a credential, e.g. ?access_token=… or &api_key=…. Already masked
# values ("abc•••••• [20 chars]") are skipped so masking twice changes nothing.
_SECRET_QUERY_VALUE = re.compile(r'(?i)([?&;][\w.-]*(?:token|key|secret|passw(?:or)?d|pwd|auth|signature|sig|session|credential)[\w.-]*=)([^&#\s"\'<>•]{4,})')
# Quoted assignments to secret-like names (groups: name, quote, value). Shared by the secret scanner and the masker.
GENERIC_SECRET = re.compile(
    r'''(?i)\b([\w.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?key)[\w.-]*)["']?\s*[:=]\s*(["'`])([^"'`\s•]{8,})\2'''
)
# Values that are clearly not credentials: documentation placeholders, templating, environment lookups, one repeated
# character and obvious sequential dummies (1234567890, abcdefghij…).
PLACEHOLDER = re.compile(
    r'(?i)example|sample|placeholder|change[_-]?me|your[_-]|xxxx|\*{3}|<[^>]*>|\$\{|\{\{|process\.env|os\.environ|dummy|redacted|replace|test[_-]?key'
    r'|0123456789|1234567890|abcdefghij|^(.)\1+$'
)


def is_placeholder(name: str, value: str) -> bool:
    return bool(PLACEHOLDER.search(value)) or value.lower() == name.lower()


def _mask_assignment(match: 're.Match[str]') -> str:
    name, quote, value = match.group(1), match.group(2), match.group(3)
    if is_placeholder(name, value):
        return match.group(0)
    return match.group(0)[: match.start(3) - match.start()] + mask_secret(value) + quote


def redact_secrets(text: str) -> str:
    """Mask credential-shaped values: known key formats, quoted assignments to secret-like names and secret-looking URL query values."""
    for _, pattern in CREDENTIAL_FORMATS:
        if pattern.pattern.startswith('-----'):
            continue  # The PEM header itself is not secret; the key material on later lines never reaches events.
        text = pattern.sub(lambda match: mask_secret(match.group(0)), text)
    text = GENERIC_SECRET.sub(_mask_assignment, text)
    return _SECRET_QUERY_VALUE.sub(lambda match: match.group(1) + mask_secret(match.group(2)), text)


def mask_values(text: str, values: Sequence[str]) -> str:
    """Replace every known secret value in ``text`` with its masked form, longest first so overlapping values stay hidden."""
    for value in sorted(set(values), key=lambda item: (-len(item), item)):
        if value in text:
            text = text.replace(value, mask_secret(value))
    return text


def _clean_quoted_text(finding: Finding, clean: Callable[[str], str]) -> Finding:
    """Apply ``clean`` to every field that quotes the site or the code: title, URL, element, excerpt and evidence source."""

    def apply(text: Optional[str]) -> Optional[str]:
        return clean(text) if text else text

    location, evidence = finding.location, finding.evidence
    return finding.model_copy(
        update={
            'title': apply(finding.title),
            'location': location.model_copy(update={'url': apply(location.url), 'element': apply(location.element)}),
            'evidence': evidence.model_copy(update={'snippet': apply(evidence.snippet), 'captured_output': apply(evidence.captured_output)}),
        }
    )


def redact_finding(finding: Finding) -> Finding:
    return _clean_quoted_text(finding, redact_secrets)


def mask_finding(finding: Finding, values: Sequence[str]) -> Finding:
    """The finding with every value in ``values`` masked wherever it is quoted."""
    return _clean_quoted_text(finding, lambda text: mask_values(text, values))


# Everything in a source file that is not code: comments, and string literals (which may span lines). The leftmost token
# wins, so a quote inside a comment or a comment marker inside a string is never misread. A single-line string that is
# never closed ends at its line.
# A regex literal is consumed whole (it stays code), so a quote or // inside it cannot open a string or a comment. It is only
# read as a literal where an operator, bracket or ``return`` precedes the slash; ``a / b`` and ``/*`` are never matched.
_JS_REGEX = r'(?:^|[=(,:;!&|?{}\[]|\breturn)[ \t]*/(?![/*])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/[a-z]*'
# A quote that is never closed on its line (JSX text such as Don't) is not a string, as in the old per-line rule.
_JS_TOKENS = re.compile(
    r'//[^\n]*'
    r'|/\*.*?(?:\*/|\Z)'
    r'|<!--.*?(?:-->|\Z)'
    r'|`(?:\\.|[^`\\])*(?:`|\Z)'
    + '|' + _JS_REGEX
    + r'|"(?:\\.|[^"\\\n])*"'
    r"|'(?:\\.|[^'\\\n])*'",
    re.S | re.M,
)
_PY_TOKENS = re.compile(
    r'#[^\n]*'
    r"|'''.*?(?:'''|\Z)"
    r'|""".*?(?:"""|\Z)'
    r'|"(?:\\.|[^"\\\n])*"?'
    r"|'(?:\\.|[^'\\\n])*'?",
    re.S,
)
# Every character str.splitlines() treats as a line break stays in place, so line numbers still match the file.
_NOT_LINE_BREAK = re.compile('[^\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]')


def _blank(text: str) -> str:
    return _NOT_LINE_BREAK.sub(' ', text)


@dataclass
class Tokens:
    """Views of one source file that keep every offset, line length and line break of the original."""

    code: str  # string-literal contents and comments blanked; quotes are kept so innerHTML = '' still reads as a constant
    uncommented: str  # comments blanked, string literals kept
    comments: str  # everything except comments blanked

    @cached_property
    def code_lines(self) -> List[str]:
        return self.code.splitlines()

    @cached_property
    def uncommented_lines(self) -> List[str]:
        return self.uncommented.splitlines()

    @cached_property
    def comment_lines(self) -> List[str]:
        return self.comments.splitlines()

    def is_code(self, offset: int) -> bool:
        """Whether the non-blank character at ``offset`` is code rather than part of a string literal or comment."""
        return self.code[offset] != ' '


def tokenize(text: str, python: bool) -> Tokens:
    """Blank string literals and comments in one pass over a file, keeping line numbers and line lengths.

    JS/TS: '…', "…", `…` (across lines), // and /* */, plus <!-- --> in templates. Python: '…', "…", triple-quoted strings and #.
    """
    code: List[str] = []
    uncommented: List[str] = []
    comments: List[str] = []
    position = 0
    for match in (_PY_TOKENS if python else _JS_TOKENS).finditer(text):
        between = text[position : match.start()]
        token = match.group(0)
        code.append(between)
        uncommented.append(between)
        comments.append(_blank(between))
        if token.startswith(('#', '//', '/*', '<!--')):
            code.append(_blank(token))
            uncommented.append(_blank(token))
            comments.append(token)
        elif not python and token[0] not in '\'"`':
            # A regex literal (with the operator before it): code, kept as it is.
            code.append(token)
            uncommented.append(token)
            comments.append(_blank(token))
        else:
            quote = token[:3] if python and token.startswith(("'''", '"""')) else token[0]
            closed = len(token) >= 2 * len(quote) and token.endswith(quote)
            inner = token[len(quote) : len(token) - len(quote)] if closed else token[len(quote) :]
            code.append(quote + _blank(inner) + (quote if closed else ''))
            uncommented.append(token)
            comments.append(_blank(token))
        position = match.end()
    tail = text[position:]
    code.append(tail)
    uncommented.append(tail)
    comments.append(_blank(tail))
    return Tokens(''.join(code), ''.join(uncommented), ''.join(comments))


def plural(count: int, word: str, plural_word: Optional[str] = None) -> str:
    return f'{count} {word if count == 1 else plural_word or word + "s"}'
