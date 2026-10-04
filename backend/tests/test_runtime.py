import socket

import pytest

from backend.analyzers.common import ScanError
from backend.analyzers.runtime import run_runtime_analysis

from .helpers import make_context, page, titles


def test_broken_link_reports_status_and_the_line_that_links_to_it(site):
    site.add('/', page('<nav>\n<a href="/docs">Docs</a>\n<a href="/boom">Boom</a>\n</nav>'))
    site.add('/boom', 'oops', status=500)

    result = run_runtime_analysis(make_context(site.url + '/'))

    by_title = {finding.title: finding for finding in result.findings}
    missing = by_title['Broken link: /docs returns HTTP 404']
    assert missing.severity.value == 'medium'
    assert missing.verification.value == 'confirmed'
    assert '/ L6: <a href="/docs">Docs</a>' in missing.evidence.snippet
    assert 'GET ' + site.url + '/docs -> 404' in missing.evidence.snippet
    assert by_title['Broken link: /boom returns HTTP 500'].severity.value == 'high'


def test_only_unlabelled_controls_are_reported_with_their_source_line(site):
    site.add(
        '/',
        page(
            '<form>\n'
            '<label>Name <input name="name"></label>\n'
            '<label for="email">Email</label><input id="email">\n'
            '<input aria-label="Search">\n'
            '<input type="hidden" name="csrf">\n'
            '<button type="submit">Go</button>\n'
            '<input name="phone">\n'
            '</form>'
        ),
    )

    result = run_runtime_analysis(make_context(site.url + '/'))

    [finding] = [f for f in result.findings if f.title == 'Form controls have no accessible label']
    assert finding.evidence.occurrences == 1
    assert finding.evidence.snippet == '/ L11: <input name="phone">'
    assert finding.location.line_start == 11


def test_error_text_needs_a_real_error_signature_in_visible_text(site):
    site.add('/', page('<p>Exceptional service, no exceptions.</p>\n<script>console.log("TypeError: fake")</script>\n<a href="/broken">x</a>'))
    site.add('/broken', page('<pre>Traceback (most recent call last):\n  File "app.py", line 3</pre>'))

    result = run_runtime_analysis(make_context(site.url + '/'))

    errors = [f for f in result.findings if f.title == 'Error or stack-trace text is visible on the page']
    assert len(errors) == 1
    assert errors[0].location.url == site.url + '/broken'
    assert 'Traceback (most recent call last)' in errors[0].evidence.snippet


def test_site_wide_issue_is_one_finding_listing_every_page(site):
    site.add('/', page('<a href="/a">A</a>', lang=''))
    site.add('/a', page('A page', lang=''))

    result = run_runtime_analysis(make_context(site.url + '/'))

    [finding] = [f for f in result.findings if f.title == '<html> element has no lang attribute']
    assert finding.evidence.occurrences == 2
    assert finding.evidence.snippet.splitlines() == ['/ L2: <html lang>', '/a L2: <html lang>']


def test_crawl_honours_max_pages_and_says_what_was_not_checked(site):
    site.add('/', page(''.join(f'<a href="/p{i}">P{i}</a>' for i in range(5))))
    for i in range(5):
        site.add(f'/p{i}', page(f'Page {i}'))

    result = run_runtime_analysis(make_context(site.url + '/', max_pages=3))

    assert result.scanned == 3
    assert sum(site.hits.values()) == 3
    assert any('3 more same-origin links not requested' in note for note in result.notes)


def test_each_url_is_requested_once_even_with_fragments(site):
    site.add('/', page('<a href="/a#one">1</a><a href="/a#two">2</a><a href="/a">3</a>'))
    site.add('/a', page('A'))

    run_runtime_analysis(make_context(site.url + '/'))

    assert site.hits['/a'] == 1


def test_unreachable_target_fails_with_a_clear_reason():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]

    with pytest.raises(ScanError, match='connection refused'):
        run_runtime_analysis(make_context(f'http://127.0.0.1:{port}/'))


def test_clean_page_has_no_findings(site):
    site.add('/', page('<main><h1>Hello</h1><img src="a.png" alt="Logo"></main>'))

    assert titles(run_runtime_analysis(make_context(site.url + '/')).findings) == []


def test_public_mode_respects_robots_txt(site):
    site.add('/robots.txt', 'User-agent: *\nDisallow: /private\n', content_type='text/plain')
    site.add('/', page('<a href="/private/admin">Admin</a><a href="/open">Open</a>'))
    site.add('/open', page('Open'))

    result = run_runtime_analysis(make_context(site.url + '/', public=True))

    assert site.hits['/private/admin'] == 0
    assert site.hits['/open'] == 1
    assert any('robots.txt disallows' in note for note in result.notes)
