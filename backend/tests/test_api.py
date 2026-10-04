import json
import socket
import time

import pytest
from fastapi.testclient import TestClient

from backend.app import app

from .helpers import page, write_files

client = TestClient(app)


def start(site_url, repo=None, **extra):
    payload = {'target_url': site_url, 'repo_path': repo, 'authorization_confirmed': True, 'inspection_mode': 'localhost', **extra}
    response = client.post('/api/scans', json=payload)
    assert response.status_code == 200, response.text
    return response.json()['scan_id']


def wait(scan_id, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get(f'/api/scans/{scan_id}').json()
        if status['status'] == 'completed':
            return status
        time.sleep(0.05)
    raise AssertionError('scan did not complete')


@pytest.fixture
def repo(tmp_path):
    return write_files(tmp_path, {'app.js': "setInterval(tick, 1000);\nconst token = 'q8f7a6s5d4f3g2h1';\n"})


def test_scan_reports_coverage_for_every_module_and_fetches_the_target_once(site, repo):
    site.add('/', page('<a href="/about">About</a>'))
    site.add('/about', page('About'))

    status = wait(start(site.url + '/', str(repo), max_pages=5, timeout_seconds=3))

    assert status['options'] == {'max_pages': 5, 'timeout_seconds': 3.0}
    for module in ('runtime', 'static', 'security', 'compliance'):
        report = status['modules'][module]
        assert report['state'] == 'done', (module, report)
        assert report['duration_ms'] is not None and report['scanned_label']
        assert status['module_status'][module] == 'done'
    # runtime, security and compliance all inspect the target page, but it is downloaded once per scan.
    assert site.hits['/'] == 1

    findings = client.get(f'/api/scans/{status["id"]}/findings').json()
    assert status['summary']['total_findings'] == len(findings)
    for finding in findings:
        assert finding['evidence']['snippet'] and finding['evidence']['check'] and finding['evidence']['captured_output']
        assert finding['location']['file'] or finding['location']['url']


def test_unreachable_target_shows_failed_modules_not_zero_issues():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]

    status = wait(start(f'http://127.0.0.1:{port}/'))

    assert status['modules']['static']['state'] == 'skipped'
    for module in ('runtime', 'security', 'compliance'):
        assert status['modules'][module]['state'] == 'failed'
        assert 'connection refused' in status['modules'][module]['error']


def test_reports_are_real_markdown_and_json(site):
    site.add('/', page('<input name="q">'))
    scan_id = wait(start(site.url + '/'))['id']

    markdown = client.get(f'/api/scans/{scan_id}/report?format=markdown')
    assert markdown.headers['content-type'].startswith('text/markdown')
    assert markdown.text.startswith('# Inspection report')
    assert '## Coverage' in markdown.text and '| runtime | done |' in markdown.text
    assert 'Form controls have no accessible label' in markdown.text

    report = client.get(f'/api/scans/{scan_id}/report?format=json')
    assert report.headers['content-type'] == 'application/json'
    assert json.loads(report.text)['id'] == scan_id


def test_review_rules_are_enforced_by_the_api(site):
    site.add('/', page('<input name="q">'))
    scan_id = wait(start(site.url + '/'))['id']
    finding_id = client.get(f'/api/scans/{scan_id}/findings').json()[0]['id']

    assert client.patch(f'/api/findings/{finding_id}/review', json={'decision': 'rejected'}).status_code == 400
    assert client.patch(f'/api/findings/{finding_id}/fix-review', json={'decision': 'approved'}).status_code == 400

    assert client.patch(f'/api/findings/{finding_id}/review', json={'decision': 'confirmed', 'reviewer': 'ana'}).status_code == 200
    approved = client.patch(f'/api/findings/{finding_id}/fix-review', json={'decision': 'approved', 'reviewer': 'ana'})
    assert approved.json()['fix_review']['decision'] == 'approved'

    escalated = client.patch(f'/api/findings/{finding_id}/review', json={'decision': 'escalated', 'reason': 'needs owner'}).json()
    assert escalated['review']['reason'] == 'needs owner'
    assert escalated['fix_review']['decision'] == 'pending'


@pytest.mark.parametrize(
    'payload, message',
    [
        ({'target_url': 'http://example.com/'}, 'Localhost mode only accepts'),
        ({'target_url': 'ftp://localhost/'}, 'http:// or https://'),
        ({'authorization_confirmed': False}, 'Authorization confirmation'),
        ({'repo_path': 'relative/path'}, 'must be absolute'),
        ({'repo_path': '/definitely/not/here'}, 'not a directory'),
        ({'inspection_mode': 'public-readonly', 'target_url': 'https://example.com/', 'repo_path': '/tmp'}, 'only available in localhost mode'),
    ],
)
def test_invalid_scan_requests_are_rejected(payload, message):
    body = {'target_url': 'http://localhost:3000/', 'authorization_confirmed': True, 'inspection_mode': 'localhost', **payload}
    response = client.post('/api/scans', json=body)
    assert response.status_code == 400
    assert message in response.json()['detail']


def test_scan_limits_are_bounded():
    response = client.post('/api/scans', json={'target_url': 'http://localhost:3000/', 'authorization_confirmed': True, 'max_pages': 500})
    assert response.status_code == 422


def test_cors_does_not_trust_arbitrary_websites():
    response = client.options('/api/scans', headers={'Origin': 'https://evil.example', 'Access-Control-Request-Method': 'POST'})
    assert 'access-control-allow-origin' not in response.headers
    allowed = client.options('/api/scans', headers={'Origin': 'http://localhost:5173', 'Access-Control-Request-Method': 'POST'})
    assert allowed.headers['access-control-allow-origin'] == 'http://localhost:5173'
