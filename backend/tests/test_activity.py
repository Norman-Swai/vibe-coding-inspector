import json
import subprocess

from backend.analyzers import security
from backend.analyzers.compliance import run_compliance_analysis
from backend.analyzers.repo import RepoIndex
from backend.analyzers.runtime import run_runtime_analysis
from backend.analyzers.security import run_npm_audit, run_security_analysis
from backend.analyzers.static_analysis import analyse_repo_with_stats
from backend.context import MAX_MESSAGE_CHARS, MAX_URL_CHARS
from backend.orchestrator import MAX_ACTIVITY_CHARS_PER_SCAN, ScanStore
from backend.schemas import ActivityEvent, ActivityKind, ActivityPage, ScanRequest

from .helpers import make_context, page, write_files


def events(context):
    return context.activity.events


def test_hostile_encodings_and_headers_cannot_break_the_crawl(site):
    # utf-7 can decode to lone surrogates; '²' passes str.isdigit() but not int(). Neither may fail a module.
    site.add('/', page('<a href="/legacy">Legacy</a><a href="/logo">Logo</a>'))
    site.add('/legacy', '<html><head><title>Legacy +2AA- page</title></head><body>old</body></html>', content_type='text/html; charset=utf-7')
    site.add('/logo', '', content_type='image/png', headers={'Content-Length': '²'})
    context = make_context(site.url + '/')

    run_runtime_analysis(context)
    run_compliance_analysis(context)

    requests = {event.request.url: event.request for event in events(context) if event.request}
    assert requests[site.url + '/logo'].bytes is None
    assert requests[site.url + '/legacy'].status == 200
    ActivityPage(events=events(context), next_seq=len(events(context))).model_dump_json()  # serialisable


def test_event_text_is_bounded_and_secrets_in_urls_are_masked(site):
    secret_link = '/report?access_token=abcdef1234567890&page=2'
    site.add('/', page(f'<a href="{secret_link}">Report</a><a href="/{"x" * 5000}">Long</a>'))
    site.add(secret_link, page('ok'))
    context = make_context(site.url + '/')

    run_runtime_analysis(context)

    for event in events(context):
        assert len(event.message) <= MAX_MESSAGE_CHARS
        assert 'abcdef1234567890' not in event.message + (event.output or '')
        if event.request:
            assert len(event.request.url) <= MAX_URL_CHARS
            assert 'abcdef1234567890' not in event.request.url
    assert any('access_token=abc••••••' in (event.request.url if event.request else '') for event in events(context))


def test_store_caps_total_activity_size_per_scan():
    store = ScanStore()
    record = store.create(ScanRequest(target_url='http://localhost/', authorization_confirmed=True))
    big = 'x' * 4000
    count = MAX_ACTIVITY_CHARS_PER_SCAN // 4000 + 10
    for seq in range(1, count + 1):
        store.append_event(record.id, ActivityEvent(seq=seq, at_ms=0, kind=ActivityKind.step, message='m', output=big))
    page_ = store.activity_since(record.id, 0)
    assert page_.dropped > 0
    assert sum(len(event.output or '') for event in page_.events) <= MAX_ACTIVITY_CHARS_PER_SCAN
    assert store.read(record.id, lambda r: r.last_activity) == 'm'


def test_runtime_check_events_name_the_full_page_url_for_tracing(site):
    site.add('/', page('<input name="q">'))
    context = make_context(site.url + '/')
    run_runtime_analysis(context)
    inspected = [event for event in events(context) if event.message.startswith('Inspected ')]
    assert [event.message for event in inspected] == [f'Inspected {site.url}/']
    assert 'unlabelled form controls: 1' in inspected[0].output


def test_risky_pattern_summary_counts_files_not_findings(site, tmp_path):
    site.add('/', page('ok'))
    repo = write_files(tmp_path, {'app.js': 'eval(userInput);\nnew Function(userInput);\nel.innerHTML = userInput;\n'})
    context = make_context(site.url + '/', repo=repo)
    run_security_analysis(context)
    messages = [event.message for event in events(context)]
    assert 'Risky code patterns: 3 matches in 1 file across 6 rules' in messages


def test_import_summary_separates_resolved_and_missing_and_ignores_comments(tmp_path):
    repo = write_files(
        tmp_path,
        {
            'app.js': "import a from './exists';\nimport b from './missing-one';\n// import c from './commented';\nimport d from './missing-two';\n",
            'exists.js': 'export default 1;\n',
        },
    )
    findings, _, stats = analyse_repo_with_stats(RepoIndex(repo))
    assert 'Relative imports checked on disk: 3 (1 resolved, 2 missing)' in stats
    [unresolved] = [f for f in findings if f.title == 'Import points to a file that does not exist']
    assert unresolved.evidence.occurrences == 2


class _Completed:
    def __init__(self, returncode, stdout, stderr=''):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _lockfile_repo(tmp_path):
    return RepoIndex(write_files(tmp_path, {'package.json': '{"name": "x"}', 'package-lock.json': '{"lockfileVersion": 3}'}))


def test_failed_npm_audit_is_reported_as_a_failure_with_its_reason(tmp_path, monkeypatch):
    stdout = json.dumps({'message': 'request to http://127.0.0.1:9/-/npm/v1/security/audits/quick failed, reason: connect ECONNREFUSED', 'error': {'summary': '', 'detail': ''}})
    monkeypatch.setattr(security.shutil, 'which', lambda _: '/usr/bin/npm')
    monkeypatch.setattr(security.subprocess, 'run', lambda *a, **k: _Completed(1, stdout, 'npm error audit endpoint returned an error'))

    audit = run_npm_audit(_lockfile_repo(tmp_path))

    assert audit.failed and 'ECONNREFUSED' in audit.reason
    assert audit.headline().endswith(f'exit 1, audit failed: {audit.reason}')
    assert 'vulnerable package' not in audit.headline()
    assert 'ECONNREFUSED' in audit.output and 'npm error audit endpoint' in audit.output
    assert 'ECONNREFUSED' in audit.note


def test_npm_audit_timeout_is_a_failure(tmp_path, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('npm', 90)

    monkeypatch.setattr(security.shutil, 'which', lambda _: '/usr/bin/npm')
    monkeypatch.setattr(security.subprocess, 'run', timeout)
    audit = run_npm_audit(_lockfile_repo(tmp_path))
    assert audit.failed and 'audit failed: timed out' in audit.headline()


def test_failed_npm_audit_is_logged_as_an_error_event(site, tmp_path, monkeypatch):
    site.add('/', page('ok'))
    monkeypatch.setattr(security.shutil, 'which', lambda _: '/usr/bin/npm')
    monkeypatch.setattr(security.subprocess, 'run', lambda *a, **k: _Completed(1, '{"error": {"summary": "offline"}}'))
    context = make_context(site.url + '/', repo=_lockfile_repo(tmp_path).root)
    run_security_analysis(context)
    [audit_event] = [event for event in events(context) if event.message.startswith('$ npm audit')]
    assert audit_event.kind == ActivityKind.error
    assert audit_event.message.endswith('audit failed: offline')
