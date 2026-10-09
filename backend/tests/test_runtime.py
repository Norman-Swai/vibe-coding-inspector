import socket

import pytest

from backend.analyzers.common import ScanError
from backend.analyzers.runtime import run_runtime_analysis
from backend.schemas import ActivityKind

from .helpers import FixtureSite, make_context, page, titles


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
    assert site.requests[0] == '/robots.txt'
    assert '1 URL skipped because robots.txt disallows it.' in result.notes


def test_public_mode_reads_robots_txt_first_and_never_requests_a_disallowed_start_url(site):
    site.add('/robots.txt', 'User-agent: *\nDisallow: /\n', content_type='text/plain')
    site.add('/', page('<a href="/about">About</a>'))
    context = make_context(site.url + '/', public=True)

    with pytest.raises(ScanError, match='robots.txt disallows .*; public read-only mode does not fetch it'):
        run_runtime_analysis(context)

    assert site.requests == ['/robots.txt']
    assert (ActivityKind.warning, f'robots.txt disallows {site.url}/; public read-only mode does not fetch it') in [
        (event.kind, event.message) for event in context.activity.events
    ]


def test_robots_lookup_is_logged_as_a_check_not_as_a_failed_page_request(site):
    site.add('/', page('ok'))
    context = make_context(site.url + '/', public=True)

    run_runtime_analysis(context)

    assert site.requests[:2] == ['/robots.txt', '/']
    [lookup] = [event for event in context.activity.events if event.request and event.request.url.endswith('/robots.txt')]
    assert lookup.kind == ActivityKind.check
    assert lookup.message == 'robots.txt not found (404); all paths allowed'
    assert lookup.request.status == 404


def test_localhost_scan_refuses_a_target_that_redirects_to_another_host(site):
    site.add('/', '', status=302, headers={'Location': 'http://example.com/'})
    context = make_context(site.url + '/')

    with pytest.raises(ScanError, match='redirect to example.com blocked: localhost mode only contacts local hosts'):
        run_runtime_analysis(context)

    [event] = [event for event in context.activity.events if event.request]
    assert event.kind == ActivityKind.warning
    assert event.request.error == 'redirect to example.com blocked: localhost mode only contacts local hosts'


def test_public_mode_does_not_analyse_a_redirect_target_that_robots_txt_disallows(site):
    site.add('/robots.txt', 'User-agent: *\nDisallow: /app\n', content_type='text/plain')
    site.add('/', '', status=302, headers={'Location': '/app'})
    site.add('/app', page('<a href="/app/more">More</a>'))
    context = make_context(site.url + '/', public=True)

    with pytest.raises(ScanError, match=f'robots.txt disallows {site.url}/app, which {site.url}/ redirected to; public read-only mode does not analyse it'):
        run_runtime_analysis(context)
    with pytest.raises(ScanError, match='redirected to; public read-only mode does not analyse it'):
        context.target_page()

    # The redirect is followed before the destination is known; nothing on the disallowed page is requested afterwards.
    assert site.requests == ['/robots.txt', '/', '/app']


def test_public_mode_reads_the_robots_txt_of_the_origin_a_target_redirects_to(site):
    other = FixtureSite()
    try:
        other.add('/robots.txt', 'User-agent: *\nDisallow: /landing\n', content_type='text/plain')
        other.add('/landing', page('<a href="/landing/next">Next</a>'))
        site.add('/', '', status=302, headers={'Location': other.url + '/landing'})
        context = make_context(site.url + '/', public=True)

        with pytest.raises(ScanError, match=f'robots.txt disallows {other.url}/landing, which {site.url}/ redirected to'):
            run_runtime_analysis(context)

        assert site.requests == ['/robots.txt', '/']
        assert other.requests == ['/landing', '/robots.txt']
        assert other.hits['/landing/next'] == 0
        # One lookup per origin, shared by every module.
        with pytest.raises(ScanError):
            context.target_page()
        assert other.hits['/robots.txt'] == 1
    finally:
        other.close()
