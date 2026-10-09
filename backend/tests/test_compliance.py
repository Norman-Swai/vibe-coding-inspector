from backend.analyzers.compliance import run_compliance_analysis

from .helpers import make_context, page, titles


def test_links_on_any_crawled_page_count_and_missing_ones_list_what_was_searched(site):
    site.add('/', page('<nav><a href="/about">About us</a></nav>'))
    site.add('/about', page('<footer><a href="/legal/privacy-policy">Privacy</a><a href="mailto:hi@example.com">Email</a></footer>'))
    site.add('/legal/privacy-policy', page('Policy'))

    result = run_compliance_analysis(make_context(site.url + '/'))

    assert titles(result.findings) == ['No terms of service link found']
    snippet = result.findings[0].evidence.snippet
    assert snippet.startswith('Keywords searched: terms, conditions, tos\nPages crawled (3):')
    assert f'{site.url}/about L5: <a href="mailto:hi@example.com">Email</a>' in snippet
    assert any(note.startswith('Found privacy policy') for note in result.notes)


def test_cookie_consent_is_only_required_when_cookies_or_trackers_are_seen(site):
    links = '<a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a><a href="/about">About</a>'
    for path in ('/privacy', '/terms', '/contact', '/about'):
        site.add(path, page(path))
    site.add('/', page(links))
    assert titles(run_compliance_analysis(make_context(site.url + '/')).findings) == []

    site.add('/', page(links + '<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'), headers={'Set-Cookie': 'uid=12345; Path=/'})
    [finding] = run_compliance_analysis(make_context(site.url + '/')).findings
    assert finding.title == 'Cookies or trackers without a visible consent mechanism'
    assert 'Set-Cookie: uid=…' in finding.evidence.snippet
    assert 'Google Tag Manager' in finding.evidence.snippet

    site.add('/', page(links + '<script src="https://consent.cookiebot.com/uc.js"></script>'), headers={'Set-Cookie': 'uid=12345; Path=/'})
    assert run_compliance_analysis(make_context(site.url + '/')).findings == []


def test_matched_links_are_verified_against_the_crawl(site):
    site.add('/', page('<footer>\n<a href="/privacy">Privacy</a>\n<a href="/terms">Terms</a>\n<a href="mailto:hi@example.com">Contact</a>\n<a href="https://example.org/about">About</a>\n</footer>'))
    site.add('/terms', page('Terms'))

    result = run_compliance_analysis(make_context(site.url + '/'))

    [broken] = result.findings
    assert broken.title == 'Privacy policy link is broken (HTTP 404)'
    assert broken.severity.value == 'medium' and broken.verification.value == 'confirmed'
    assert (broken.location.url, broken.location.line_start, broken.location.element) == (site.url + '/', 6, '<a href="/privacy">Privacy</a>')
    assert f'GET {site.url}/privacy -> 404' in broken.evidence.snippet
    assert f'Broken link: privacy policy → {site.url}/privacy (HTTP 404)' in result.notes
    assert f'Found terms of service → {site.url}/terms (verified, HTTP 200)' in result.notes
    assert 'Found contact information → mailto:hi@example.com (not verified: mailto: link)' in result.notes
    assert 'Found about page → https://example.org/about (not verified: off-site)' in result.notes


def test_links_the_crawl_did_not_request_are_found_but_not_verified(site):
    site.add('/robots.txt', 'User-agent: *\nDisallow: /privacy\n', content_type='text/plain')
    site.add('/', page('<a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a><a href="/about">About</a>'))
    for path in ('/terms', '/contact', '/about'):
        site.add(path, page(path))

    result = run_compliance_analysis(make_context(site.url + '/', public=True, max_pages=2))

    assert result.findings == []
    assert site.hits['/privacy'] == 0
    assert f'Found privacy policy → {site.url}/privacy (not verified: robots.txt disallows it)' in result.notes
    assert f'Found terms of service → {site.url}/terms (verified, HTTP 200)' in result.notes
    assert f'Found contact information → {site.url}/contact (not verified: page limit reached)' in result.notes


def test_links_that_require_authentication_are_not_reported_as_broken(site):
    site.add('/', page('<a href="/privacy">Privacy</a><a href="/terms">Terms</a>'))
    site.add('/privacy', page('Members only'), status=403)
    site.add('/terms', page('Terms'))

    result = run_compliance_analysis(make_context(site.url + '/'))

    assert [finding.title for finding in result.findings] == ['No contact information link found', 'No about page link found']
    assert f'Found privacy policy → {site.url}/privacy (not verified: requires authentication, HTTP 403)' in result.notes
    assert f'Found terms of service → {site.url}/terms (verified, HTTP 200)' in result.notes
