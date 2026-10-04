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
    site.add('/', page(links))
    assert titles(run_compliance_analysis(make_context(site.url + '/')).findings) == []

    site.add('/', page(links + '<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'), headers={'Set-Cookie': 'uid=12345; Path=/'})
    [finding] = run_compliance_analysis(make_context(site.url + '/')).findings
    assert finding.title == 'Cookies or trackers without a visible consent mechanism'
    assert 'Set-Cookie: uid=…' in finding.evidence.snippet
    assert 'Google Tag Manager' in finding.evidence.snippet

    site.add('/', page(links + '<script src="https://consent.cookiebot.com/uc.js"></script>'), headers={'Set-Cookie': 'uid=12345; Path=/'})
    assert run_compliance_analysis(make_context(site.url + '/')).findings == []
