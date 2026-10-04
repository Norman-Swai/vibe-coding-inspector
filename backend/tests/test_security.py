from backend.analyzers.repo import RepoIndex
from backend.analyzers.security import check_response, run_npm_audit, scan_env_files, scan_secrets, scan_sinks
from backend.analyzers.web import PageFetcher

from .helpers import page, titles, write_files

HARDENED = {
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
}


def fetch(site, path='/'):
    return PageFetcher(timeout=5).get(site.url + path)


def test_hardened_response_has_no_header_findings(site):
    site.add('/', page('ok'), headers=HARDENED)
    findings = check_response(fetch(site), is_public=False)
    # BaseHTTPRequestHandler always sends "Server: BaseHTTP/x.y Python/x.y", which is a real disclosure.
    assert titles(findings) == ['Response headers reveal server software']


def test_missing_headers_are_reported_with_the_headers_that_were_received(site):
    site.add('/', page('ok'))
    findings = {finding.title: finding for finding in check_response(fetch(site), is_public=False)}

    assert {'Missing Content-Security-Policy header', 'Page can be embedded in frames by any site', 'Missing X-Content-Type-Options: nosniff'} <= set(findings)
    csp = findings['Missing Content-Security-Policy header']
    assert csp.evidence.snippet.startswith('content-security-policy: (not sent)')
    assert 'content-type: text/html' in csp.evidence.snippet
    assert csp.evidence.captured_output.startswith(f'GET {site.url}/ -> 200')


def test_insecure_cookie_is_reported_with_its_value_masked(site):
    site.add('/', page('ok'), headers={**HARDENED, 'Set-Cookie': ['sessionid=abc123456789xyz; Path=/', 'theme=dark; Path=/; HttpOnly; SameSite=Lax']})
    findings = [f for f in check_response(fetch(site), is_public=False) if f.title.startswith('Cookie')]

    assert titles(findings) == ['Cookie "sessionid" is missing HttpOnly, SameSite']
    assert findings[0].severity.value == 'medium'
    assert 'abc123456789xyz' not in findings[0].evidence.snippet


def test_secret_scan_reports_every_real_secret_masked_and_skips_placeholders(tmp_path):
    aws_key = 'AKIA' + 'QWERTYUIOPASDFGH'
    write_files(
        tmp_path,
        {
            'src/config.js': f'const aws = "{aws_key}";\nconst apiKey = "q8f7a6s5d4f3g2h1";\nconst docs = "your-api-key-here";\n',
            'src/settings.py': 'password = "changeme123"\nDB_PASSWORD = os.environ["DB_PASSWORD"]\n',
            'node_modules/lib/index.js': 'const token = "zzzzzzzz-real-looking-1234";\n',
            'tests/fixtures.js': f'const token = "abcdefgh12345678";\nconst leaked = "{aws_key}";\n',
            '.env.example': 'API_KEY="abcd1234efgh5678"\n',
        },
    )

    findings = scan_secrets(RepoIndex(tmp_path))

    assert [(f.location.file, f.location.line_start, f.title) for f in findings] == [
        ('src/config.js', 1, 'AWS access key ID in source code'),
        ('src/config.js', 2, 'Possible secret assigned to "apiKey" in source code'),
        # Name-based guesses are skipped in test files, but a real credential format is still reported there.
        ('tests/fixtures.js', 2, 'AWS access key ID in source code'),
    ]
    assert findings[0].severity.value == 'critical' and findings[0].verification.value == 'confirmed'
    assert aws_key not in findings[0].evidence.snippet
    assert findings[0].evidence.snippet.startswith('L1: const aws = "AKI••••••')


def test_html_sinks_ignore_constants_comments_and_sanitised_values(tmp_path):
    write_files(
        tmp_path,
        {
            'app.js': (
                "el.innerHTML = '';\n"
                'el.innerHTML = userInput;\n'
                '// eval(fromComment)\n'
                'el.innerHTML = DOMPurify.sanitize(userInput);\n'
                'const result = eval(code);\n'
                'const help = "never call eval(x) or set .innerHTML = y";\n'
            ),
        },
    )

    findings = {f.title: f for f in scan_sinks(RepoIndex(tmp_path))}

    assert findings['HTML injection sink used without sanitising'].evidence.snippet == 'L2: el.innerHTML = userInput;'
    assert findings['Dynamic code execution with eval()'].evidence.snippet == 'L5: const result = eval(code);'


def test_env_file_must_be_git_ignored(tmp_path):
    write_files(tmp_path, {'.env': 'API_KEY=super-secret-value\nPORT=3000\n'})
    [finding] = scan_env_files(RepoIndex(tmp_path))
    assert 'API_KEY' in finding.evidence.snippet
    assert 'super-secret-value' not in finding.evidence.snippet
    assert 'PORT' not in finding.evidence.snippet

    write_files(tmp_path, {'.gitignore': 'node_modules\n.env*\n'})
    assert scan_env_files(RepoIndex(tmp_path)) == []


def test_npm_audit_explains_why_it_did_not_run(tmp_path):
    write_files(tmp_path, {'package.json': '{"name": "x"}'})
    audit = run_npm_audit(RepoIndex(tmp_path))
    assert audit.findings == [] and audit.command is None
    assert 'no package-lock.json' in audit.note
