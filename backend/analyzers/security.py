from __future__ import annotations

import dataclasses
import fnmatch
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional, Pattern, Tuple
from urllib.parse import urlparse

from ..schemas import ActivityKind, Finding, Location, ModuleName, Severity, Verification
from .common import CREDENTIAL_FORMATS, AnalyzerResult, Rule, code_only, is_comment_line, mask_secret, new_finding, numbered_lines, plural, truncate
from .repo import RepoIndex
from .web import FetchResult

if TYPE_CHECKING:
    from ..context import ScanContext

MODULE = ModuleName.security
JS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.html'}
PY = {'.py'}
MAX_SECRET_FINDINGS = 50


# --- HTTP response checks -------------------------------------------------------------------------------------------

MISSING_CSP = Rule(
    title='Missing Content-Security-Policy header',
    severity=Severity.medium,
    verification=Verification.confirmed,
    check='The main document response must include a Content-Security-Policy header.',
    description='The page is served without a Content Security Policy.',
    impact='Without CSP, any injected script runs with full page privileges, so a single XSS bug is fully exploitable.',
    fix="Add a Content-Security-Policy header; start with default-src 'self' and tighten from there.",
    cwe='CWE-693',
)
FRAMEABLE = Rule(
    title='Page can be embedded in frames by any site',
    severity=Severity.medium,
    verification=Verification.confirmed,
    check='The response must send X-Frame-Options (DENY or SAMEORIGIN) or a CSP frame-ancestors directive.',
    description='Nothing stops other websites from loading this page inside an invisible frame.',
    impact='Attackers can overlay the page and trick users into clicking buttons (clickjacking).',
    fix="Send X-Frame-Options: DENY, or Content-Security-Policy: frame-ancestors 'self'.",
    cwe='CWE-1021',
)
MISSING_NOSNIFF = Rule(
    title='Missing X-Content-Type-Options: nosniff',
    severity=Severity.low,
    verification=Verification.confirmed,
    check='The response must send X-Content-Type-Options: nosniff.',
    description='Browsers may guess ("sniff") content types instead of trusting the declared one.',
    impact='Uploaded or user-controlled files can be interpreted as scripts or HTML.',
    fix='Send X-Content-Type-Options: nosniff on every response.',
    cwe='CWE-693',
)
MISSING_HSTS = Rule(
    title='Missing Strict-Transport-Security header',
    severity=Severity.medium,
    verification=Verification.confirmed,
    check='HTTPS responses must send Strict-Transport-Security so browsers refuse plain-HTTP downgrades.',
    description='The HTTPS site does not tell browsers to always use HTTPS.',
    impact='The first request over an untrusted network can be downgraded to HTTP and intercepted.',
    fix='Send Strict-Transport-Security: max-age=31536000; includeSubDomains.',
    cwe='CWE-319',
)
PLAIN_HTTP = Rule(
    title='Public site is served over plain HTTP',
    severity=Severity.high,
    verification=Verification.confirmed,
    check='Public targets must be served over HTTPS or redirect to it.',
    description='The page loaded over unencrypted HTTP and did not redirect to HTTPS.',
    impact='Anyone on the network path can read or modify the page and any data users submit.',
    fix='Serve the site over HTTPS and redirect all HTTP requests to it.',
    cwe='CWE-319',
)
VERSION_DISCLOSURE = Rule(
    title='Response headers reveal server software',
    severity=Severity.low,
    verification=Verification.confirmed,
    check='Server and X-Powered-By headers should not reveal product names with versions.',
    description='The response advertises the server software and version.',
    impact='Attackers can look up known vulnerabilities for that exact version.',
    fix='Remove X-Powered-By and strip version numbers from the Server header.',
    cwe='CWE-200',
)
CORS_WILDCARD = Rule(
    title='CORS allows any origin together with credentials',
    severity=Severity.high,
    verification=Verification.confirmed,
    check='Access-Control-Allow-Origin "*" must not be combined with Access-Control-Allow-Credentials: true.',
    description='The response opens cross-origin access to every website while also allowing credentials.',
    impact='This signals a CORS policy that is not restricted to trusted origins.',
    fix='Return an explicit allow-list of trusted origins instead of "*".',
    cwe='CWE-942',
)
INSECURE_COOKIE = Rule(
    title='Cookie is missing security attributes',
    severity=Severity.medium,
    verification=Verification.confirmed,
    check='Set-Cookie should include HttpOnly (unless scripts must read it), SameSite, and Secure on HTTPS sites.',
    description='A cookie set by the site lacks protective attributes.',
    impact='Without HttpOnly, injected scripts can steal the cookie; without SameSite or Secure it can be sent cross-site or over HTTP.',
    fix='Set HttpOnly, Secure and SameSite=Lax (or Strict) on session and authentication cookies.',
    cwe='CWE-1004',
)
_SESSIONISH_COOKIE = re.compile(r'(?i)sess|sid|auth|token|jwt|login|remember|user')


def _header_evidence(page: FetchResult, highlight: str) -> str:
    lines = [
        f'  {name.lower()}: {truncate(value, 140)}'
        for name, value in sorted(page.headers.items(), key=lambda item: item[0].lower())
        if name.lower() != 'set-cookie'
    ]
    lines.extend(f'  set-cookie: {truncate(_mask_cookie(raw), 140)}' for raw in page.set_cookies)
    return f'{highlight}\n\nResponse headers received:\n' + '\n'.join(lines[:24])


def _mask_cookie(set_cookie: str) -> str:
    pair, _, attributes = set_cookie.partition(';')
    name, _, value = pair.partition('=')
    masked = f'{name.strip()}={mask_secret(value.strip()) if value.strip() else ""}'
    return f'{masked};{attributes}' if attributes else masked


def check_response(page: FetchResult, is_public: bool) -> List[Finding]:
    headers = page.headers
    findings: List[Finding] = []
    location = Location(url=page.url, element='response headers')

    def add(rule: Rule, highlight: str, **overrides) -> None:
        findings.append(new_finding(MODULE, rule, location=location, snippet=_header_evidence(page, highlight), captured=page.describe(), **overrides))

    csp = headers.get('content-security-policy', '')
    if not csp:
        add(MISSING_CSP, 'content-security-policy: (not sent)')
    if not headers.get('x-frame-options') and 'frame-ancestors' not in csp.lower():
        add(FRAMEABLE, 'x-frame-options: (not sent)\ncontent-security-policy frame-ancestors: (not set)')
    if headers.get('x-content-type-options', '').strip().lower() != 'nosniff':
        add(MISSING_NOSNIFF, f'x-content-type-options: {headers.get("x-content-type-options") or "(not sent)"}')

    scheme = urlparse(page.url).scheme
    if scheme == 'https' and not headers.get('strict-transport-security'):
        add(MISSING_HSTS, 'strict-transport-security: (not sent)')
    if scheme == 'http' and is_public:
        add(PLAIN_HTTP, f'Final URL after redirects: {page.url}')

    disclosed = [
        f'{name}: {headers[name]}'
        for name in ('server', 'x-powered-by', 'x-aspnet-version')
        if headers.get(name) and (name != 'server' or re.search(r'\d+\.\d+', headers[name]))
    ]
    if disclosed:
        add(VERSION_DISCLOSURE, '\n'.join(disclosed))

    if headers.get('access-control-allow-origin', '').strip() == '*' and headers.get('access-control-allow-credentials', '').strip().lower() == 'true':
        add(CORS_WILDCARD, 'access-control-allow-origin: *\naccess-control-allow-credentials: true')

    for raw in page.set_cookies:
        findings.extend(_check_cookie(page, raw, scheme == 'https'))
    return findings


def _check_cookie(page: FetchResult, raw: str, https: bool) -> List[Finding]:
    pair, _, attribute_text = raw.partition(';')
    name = pair.partition('=')[0].strip()
    attributes = {part.strip().split('=')[0].lower() for part in attribute_text.split(';') if part.strip()}
    missing = [flag for flag, present in (('HttpOnly', 'httponly' in attributes), ('SameSite', 'samesite' in attributes), ('Secure', not https or 'secure' in attributes)) if not present]
    if not missing:
        return []
    serious = ('HttpOnly' in missing or 'Secure' in missing) and _SESSIONISH_COOKIE.search(name)
    return [
        new_finding(
            MODULE,
            INSECURE_COOKIE,
            title=f'Cookie "{name}" is missing {", ".join(missing)}',
            severity=Severity.medium if serious else Severity.low,
            location=Location(url=page.url, element=f'Set-Cookie: {name}'),
            snippet=f'Set-Cookie: {_mask_cookie(raw)}\nMissing attributes: {", ".join(missing)}',
            captured=page.describe(),
        )
    ]


# --- Repository checks ----------------------------------------------------------------------------------------------

SECRET_RULE = Rule(
    title='Hard-coded secret',
    severity=Severity.critical,
    verification=Verification.hypothesis,
    check='Source files are matched against credential formats (AWS, GitHub, Slack, Stripe, Google, OpenAI, Anthropic, private keys) and quoted assignments to secret-like names; placeholders, and name-based matches in test/fixture files, are ignored.',
    description='A source file appears to contain a credential in plain text.',
    impact='Anyone with access to the code or its history can use the credential.',
    fix='Remove the value from source, load it from the environment or a secret manager, and rotate the credential.',
    cwe='CWE-798',
)
SECRET_PATTERNS: List[Tuple[str, Pattern[str], Severity, Verification]] = [
    (label, pattern, Severity.high if label == 'Google API key' else Severity.critical, Verification.confirmed) for label, pattern in CREDENTIAL_FORMATS
]
GENERIC_SECRET = re.compile(
    r'''(?i)\b([\w.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?key)[\w.-]*)["']?\s*[:=]\s*(["'`])([^"'`\s]{8,})\2'''
)
PLACEHOLDER = re.compile(r'(?i)example|sample|placeholder|change[_-]?me|your[_-]|xxxx|\*{3}|<[^>]*>|\$\{|\{\{|process\.env|os\.environ|dummy|redacted|replace|test[_-]?key|^(.)\1+$')
_SECRET_SKIP_FILES = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'Cargo.lock', 'composer.lock', 'Gemfile.lock', 'go.sum'}
_SECRET_SKIP_SUFFIXES = ('.min.js', '.map', '.svg', '.lock')
_EXAMPLE_FILE = re.compile(r'(?i)\.(?:example|sample|template|dist)$')
_ENV_FILE = re.compile(r'^\.env(?:\.[\w-]+)?$')
_TEST_PATH = re.compile(r'(?:^|/)(?:tests?|__tests__|__mocks__|spec|fixtures?)/|(?:^|/)test_[^/]*\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.[cm]?[jt]sx?$')

SINK_RULES: List[Tuple[Rule, Pattern[str], set]] = [
    (
        Rule(
            title='Dynamic code execution with eval()',
            severity=Severity.high,
            verification=Verification.hypothesis,
            check='Source must not call eval(): it runs arbitrary strings as code.',
            description='The code evaluates a string as code at runtime.',
            impact='If any part of the string comes from users, attackers can run their own code.',
            fix='Replace eval() with explicit parsing (JSON.parse, ast.literal_eval) or a lookup table.',
            cwe='CWE-95',
        ),
        re.compile(r'(?<![\w.$])eval\s*\('),
        JS | PY,
    ),
    (
        Rule(
            title='Dynamic code execution with new Function()',
            severity=Severity.high,
            verification=Verification.hypothesis,
            check='Source must not construct functions from strings with new Function().',
            description='The code builds a function from a string at runtime.',
            impact='If any part of the string comes from users, attackers can run their own code.',
            fix='Use regular functions or a lookup table instead of compiling strings.',
            cwe='CWE-95',
        ),
        re.compile(r'\bnew\s+Function\s*\('),
        JS,
    ),
    (
        Rule(
            title='HTML injection sink used without sanitising',
            severity=Severity.medium,
            verification=Verification.hypothesis,
            check='innerHTML/outerHTML assignments, insertAdjacentHTML(), document.write() and dangerouslySetInnerHTML render strings as HTML; '
            'constant string literals and lines that call a sanitiser (DOMPurify, sanitize) are ignored.',
            description='The code renders a dynamic string as HTML.',
            impact='If the string contains user input, attackers can inject scripts (cross-site scripting).',
            fix='Render text with textContent / JSX text, or sanitise the HTML with DOMPurify first.',
            cwe='CWE-79',
        ),
        re.compile(r'\.(?:inner|outer)HTML\s*=(?!=)|\binsertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(|\bdangerouslySetInnerHTML\b'),
        JS,
    ),
    (
        Rule(
            title='Shell command run with shell=True',
            severity=Severity.high,
            verification=Verification.hypothesis,
            check='subprocess calls must not use shell=True; the command string is interpreted by a shell.',
            description='A subprocess is started through the system shell.',
            impact='Any interpolated input becomes command injection.',
            fix='Pass the command as a list of arguments and drop shell=True.',
            cwe='CWE-78',
        ),
        re.compile(r'\bshell\s*=\s*True\b'),
        PY,
    ),
    (
        Rule(
            title='TLS certificate verification disabled',
            severity=Severity.medium,
            verification=Verification.confirmed,
            check='HTTP clients must not disable certificate checks (verify=False, rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0).',
            description='The code turns off TLS certificate verification.',
            impact='Connections can be intercepted by anyone on the network path.',
            fix='Keep verification on; if you need a private CA, pass its bundle explicitly.',
            cwe='CWE-295',
        ),
        re.compile(r'\bverify\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0'),
        JS | PY,
    ),
    (
        Rule(
            title='Unsafe deserialisation with pickle',
            severity=Severity.medium,
            verification=Verification.hypothesis,
            check='pickle.load()/pickle.loads() must never receive untrusted data.',
            description='The code unpickles data.',
            impact='Unpickling attacker-controlled data executes arbitrary code.',
            fix='Use JSON or another data-only format for anything that crosses a trust boundary.',
            cwe='CWE-502',
        ),
        re.compile(r'\bpickle\.loads?\s*\('),
        PY,
    ),
]
_CONSTANT_HTML = re.compile(r'''\.(?:inner|outer)HTML\s*=\s*(?:(["'])[^"']*\1|`[^`$]*`)\s*;?\s*$''')

ENV_NOT_IGNORED = Rule(
    title='Environment file is not git-ignored',
    severity=Severity.high,
    verification=Verification.hypothesis,
    check='.env files that hold secrets must be matched by a pattern in the repository .gitignore.',
    description='An environment file with secret-looking keys exists and no .gitignore pattern excludes it.',
    impact='The file is likely to be committed, publishing every credential in it.',
    fix='Add .env* (keeping .env.example) to .gitignore, remove the file from git history, and rotate the values.',
    cwe='CWE-538',
)
NPM_AUDIT = Rule(
    title='Vulnerable dependency',
    severity=Severity.medium,
    verification=Verification.confirmed,
    check='`npm audit --json` was run against the lockfile; each reported package is listed with its advisories.',
    description='npm audit reports known security advisories for an installed dependency.',
    impact='Known vulnerabilities in dependencies have public exploits.',
    fix='Upgrade to a fixed version (npm audit fix), or replace the package.',
    cwe='CWE-1104',
)


def secret_scannable(source) -> bool:
    name = source.path.name
    return not (name in _SECRET_SKIP_FILES or name.endswith(_SECRET_SKIP_SUFFIXES) or _ENV_FILE.match(name) or source.text is None)


def scan_secrets(repo: RepoIndex) -> List[Finding]:
    findings: List[Finding] = []
    for source in repo.files:
        name = source.path.name
        if not secret_scannable(source):
            continue
        allow_generic = not (_EXAMPLE_FILE.search(name) or _TEST_PATH.search(source.rel))
        for line_no, line in enumerate(source.lines, start=1):
            for label, value, severity, verification in _secrets_in_line(line, allow_generic):
                masked_line = line.replace(value, mask_secret(value))
                findings.append(
                    new_finding(
                        MODULE,
                        dataclasses.replace(SECRET_RULE, verification=verification),
                        title=f'{label} in source code',
                        severity=severity,
                        location=Location(file=source.rel, line_start=line_no, line_end=line_no),
                        snippet=f'L{line_no}: {truncate(masked_line, 200)}',
                        captured=f'Pattern match in {source.rel} (value masked)',
                    )
                )
                if len(findings) >= MAX_SECRET_FINDINGS:
                    return findings
    return findings


def _secrets_in_line(line: str, allow_generic: bool) -> List[Tuple[str, str, Severity, Verification]]:
    hits: List[Tuple[str, str, Severity, Verification]] = []
    for label, pattern, severity, verification in SECRET_PATTERNS:
        for match in pattern.finditer(line):
            hits.append((label, match.group(0), severity, verification))
    if allow_generic and not hits:
        for match in GENERIC_SECRET.finditer(line):
            name, value = match.group(1), match.group(3)
            if PLACEHOLDER.search(value) or value.lower() == name.lower():
                continue
            hits.append((f'Possible secret assigned to "{name}"', value, Severity.high, Verification.hypothesis))
    return hits


def scan_sinks(repo: RepoIndex) -> List[Finding]:
    findings: List[Finding] = []
    for rule, pattern, suffixes in SINK_RULES:
        for source in repo.with_suffixes(suffixes):
            if source.text is None or not pattern.search(source.text):
                continue
            hits = [
                number
                for number, line in enumerate(source.lines, start=1)
                if pattern.search(code_only(line)) and not is_comment_line(line) and not _sink_is_safe(line)
            ]
            if hits:
                findings.append(
                    new_finding(
                        MODULE,
                        rule,
                        location=Location(file=source.rel, line_start=hits[0], line_end=hits[0]),
                        snippet=numbered_lines(source.lines, hits),
                        captured=f'Pattern match in {source.rel}',
                        occurrences=len(hits),
                    )
                )
    return findings


def _sink_is_safe(line: str) -> bool:
    lowered = line.lower()
    return 'dompurify' in lowered or 'sanitize' in lowered or bool(_CONSTANT_HTML.search(line))


def scan_env_files(repo: RepoIndex) -> List[Finding]:
    env_files = [source for source in repo.files if _ENV_FILE.match(source.path.name) and not _EXAMPLE_FILE.search(source.path.name)]
    if not env_files:
        return []
    gitignore = repo.root / '.gitignore'
    patterns = []
    if gitignore.is_file():
        patterns = [line.strip().lstrip('/') for line in gitignore.read_text(errors='replace').splitlines() if line.strip() and not line.startswith('#')]
    findings = []
    for source in env_files:
        if any(fnmatch.fnmatch(source.path.name, pattern) or fnmatch.fnmatch(source.rel, pattern) for pattern in patterns):
            continue
        keys = [line.split('=', 1)[0].strip() for line in source.lines if '=' in line and not line.lstrip().startswith('#')]
        secret_keys = [key for key in keys if re.search(r'(?i)key|secret|token|pass|pwd|auth|credential|dsn|database_url', key)]
        if not secret_keys:
            continue
        findings.append(
            new_finding(
                MODULE,
                ENV_NOT_IGNORED,
                location=Location(file=source.rel),
                snippet=(
                    f'{source.rel} defines: {", ".join(secret_keys[:10])} (values hidden)\n'
                    + (f'.gitignore patterns: {", ".join(patterns[:12]) or "(none)"} — none match {source.path.name}' if gitignore.is_file() else '.gitignore: not found')
                ),
                captured=f'Read {source.rel} key names and {".gitignore" if gitignore.is_file() else "no .gitignore"}',
            )
        )
    return findings


@dataclass
class AuditRun:
    """What happened when npm audit was (or was not) run, for coverage notes and the activity log."""

    findings: List[Finding] = field(default_factory=list)
    note: Optional[str] = None
    command: Optional[str] = None
    exit_code: Optional[int] = None
    output: Optional[str] = None
    # The command ran but did not produce an audit (registry unreachable, timeout, unreadable output).
    failed: bool = False
    reason: Optional[str] = None

    def headline(self) -> str:
        exit_text = f'exit {self.exit_code}' if self.exit_code is not None else 'no exit code'
        if self.failed:
            return f'$ {self.command} → {exit_text}, audit failed: {self.reason}'
        return f'$ {self.command} → {exit_text}, {plural(len(self.findings), "vulnerable package")}'


def run_npm_audit(repo: RepoIndex) -> AuditRun:
    root = repo.root
    if not (root / 'package.json').is_file():
        return AuditRun()
    if not any((root / name).is_file() for name in ('package-lock.json', 'npm-shrinkwrap.json')):
        return AuditRun(note='npm audit skipped: package.json has no package-lock.json, so installed versions are unknown.')
    npm = shutil.which('npm')
    if not npm:
        return AuditRun(note='npm audit skipped: npm is not installed on the inspector host.')
    command = f'npm audit --json   (cwd: {root})'
    try:
        completed = subprocess.run([npm, 'audit', '--json'], cwd=root, capture_output=True, text=True, timeout=90, check=False)
    except subprocess.TimeoutExpired:
        return AuditRun(
            note='npm audit failed: it did not finish within 90 seconds.', command=command, output='timed out after 90 s', failed=True, reason='timed out after 90 s'
        )
    stderr = (completed.stderr or '').strip()
    stderr_block = f'\n--- stderr ---\n{truncate(stderr, 1500)}' if stderr else ''
    try:
        payload = json.loads(completed.stdout or '{}')
    except json.JSONDecodeError:
        return AuditRun(
            note='npm audit failed: its output was not valid JSON.',
            command=command,
            exit_code=completed.returncode,
            output=truncate(completed.stdout or '', 2000) + stderr_block,
            failed=True,
            reason='output was not valid JSON',
        )
    if 'error' in payload:
        error = payload['error'] if isinstance(payload['error'], dict) else {'summary': str(payload['error'])}
        reason = truncate(str(error.get('summary') or payload.get('message') or error.get('detail') or stderr or 'unknown error'), 200)
        return AuditRun(
            note=f'npm audit failed: {reason}',
            command=command,
            exit_code=completed.returncode,
            output=truncate(json.dumps({key: payload[key] for key in ('message', 'error') if key in payload}, indent=2), 2000) + stderr_block,
            failed=True,
            reason=reason,
        )

    findings: List[Finding] = []
    for package, details in sorted(payload.get('vulnerabilities', {}).items()):
        severity_name = {'moderate': 'medium'}.get(details.get('severity'), details.get('severity'))
        severity = Severity(severity_name) if severity_name in Severity._value2member_map_ else Severity.medium
        advisories = []
        for via in details.get('via', []):
            if isinstance(via, dict):
                advisories.append(f'- {via.get("title", "advisory")} ({via.get("severity", "?")}) {via.get("url", "")}'.rstrip())
            else:
                advisories.append(f'- via dependency "{via}"')
        fix = details.get('fixAvailable')
        fix_text = 'yes' if fix is True else (f'yes — {fix.get("name")}@{fix.get("version")}' if isinstance(fix, dict) else 'no')
        findings.append(
            new_finding(
                MODULE,
                NPM_AUDIT,
                title=f'Vulnerable dependency: {package}',
                severity=severity,
                location=Location(file='package-lock.json', element=f'{package}@{details.get("range", "?")}'),
                snippet=f'{package} {details.get("range", "")} — {details.get("severity", "?")}{" (direct dependency)" if details.get("isDirect") else ""}\n'
                + '\n'.join(advisories[:6])
                + f'\nFix available: {fix_text}',
                captured='npm audit --json',
            )
        )
    metadata = payload.get('metadata', {})
    output = '\n'.join(
        [
            f'vulnerabilities: {json.dumps(metadata.get("vulnerabilities", {}))}',
            f'dependencies: {json.dumps(metadata.get("dependencies", {}))}',
            *([f'packages: {", ".join(sorted(payload.get("vulnerabilities", {}))[:30])}'] if findings else []),
            *([f'stderr: {truncate(stderr, 600)}'] if stderr else []),
        ]
    )
    return AuditRun(
        findings=findings,
        note=f'npm audit reported {plural(len(findings), "vulnerable package")}.',
        command=command,
        exit_code=completed.returncode,
        output=output,
    )


def _header_report(page: FetchResult) -> str:
    """Every security-relevant response header and whether it was sent, as shown in the activity log."""
    headers = page.headers
    csp = headers.get('content-security-policy', '')
    https = urlparse(page.url).scheme == 'https'

    def state(name: str) -> str:
        return f'{name}: {truncate(headers[name], 100)}' if headers.get(name) else f'{name}: (not sent)'

    lines = [
        state('content-security-policy'),
        state('x-frame-options') + ('  [CSP frame-ancestors present]' if 'frame-ancestors' in csp.lower() else ''),
        state('x-content-type-options'),
        state('strict-transport-security') if https else 'strict-transport-security: not applicable (http)',
        state('referrer-policy'),
        state('permissions-policy'),
        state('server'),
        state('x-powered-by'),
        state('access-control-allow-origin'),
        f'set-cookie: {plural(len(page.set_cookies), "cookie")}',
    ]
    return '\n'.join(lines)


def run_security_analysis(context: 'ScanContext') -> AnalyzerResult:
    result = AnalyzerResult()
    page = context.target_page()
    scanned_parts = ['1 page response']
    if page.ok and page.is_html:
        header_findings = check_response(page, context.is_public)
        result.findings.extend(header_findings)
        context.emit(MODULE, ActivityKind.check, f'Response headers of {page.url}: {plural(len(header_findings), "issue")}', _header_report(page))
    else:
        note = f'Header checks skipped: the target returned {page.status} {page.content_type or "(no content type)"} instead of an HTML page.'
        result.notes.append(note)
        context.emit(MODULE, ActivityKind.warning, note)
    if urlparse(page.url).scheme == 'http' and not context.is_public:
        result.notes.append('HTTPS and HSTS checks do not apply to an http:// development server in localhost mode.')

    if context.repo_path is None:
        result.notes.append('Secret, code-sink and dependency checks skipped: no repository path was provided.')
        context.emit(MODULE, ActivityKind.step, 'Repository checks skipped: no repository path was provided')
    else:
        repo = context.repo()
        secrets = scan_secrets(repo)
        result.findings.extend(secrets)
        scannable = sum(1 for source in repo.files if secret_scannable(source))
        context.emit(
            MODULE,
            ActivityKind.check,
            f'Secret scan: {plural(scannable, "text file")} searched, {plural(len(secrets), "possible secret")}',
            '\n'.join(f'{f.location.file}:{f.location.line_start}  {f.title}' for f in secrets[:20]) or None,
        )
        sinks = scan_sinks(repo)
        result.findings.extend(sinks)
        context.emit(
            MODULE,
            ActivityKind.check,
            f'Risky code patterns: {plural(len(sinks), "match", "matches")} in {plural(len({f.location.file for f in sinks}), "file")} across {len(SINK_RULES)} rules',
            '\n'.join(f'{rule.title}: {sum(1 for f in sinks if f.title == rule.title)} file(s)' for rule, _, _ in SINK_RULES),
        )
        env_findings = scan_env_files(repo)
        result.findings.extend(env_findings)
        context.emit(MODULE, ActivityKind.check, f'.env files not covered by .gitignore: {len(env_findings)}')
        audit = run_npm_audit(repo)
        result.findings.extend(audit.findings)
        if audit.command:
            # A failed run is still a command the user should see with its output, flagged as an error rather than "0 vulnerable".
            context.emit(MODULE, ActivityKind.error if audit.failed else ActivityKind.command, audit.headline(), audit.output)
        elif audit.note:
            context.emit(MODULE, ActivityKind.warning, audit.note)
        if audit.note:
            result.notes.append(audit.note)
        scanned_parts.append(plural(len(repo.files), 'file'))
        result.scanned = len(repo.files)
    result.scanned += 1
    result.scanned_label = ', '.join(scanned_parts)
    return result
