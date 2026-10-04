from backend.analyzers.web import PageFetcher, url_host

from .helpers import page


def test_url_host_is_what_the_http_client_will_connect_to():
    # urllib.parse would report "localhost" for the first URL and a valid host for the others.
    assert url_host('http://example.com\\@localhost:8765/') == 'example.com'
    assert url_host('http://localhost:99999/') is None
    assert url_host('http://local host:8765/') is None
    assert url_host('http://[::1]:3000/') == '::1'
    assert url_host('http://LOCALHOST/') == 'localhost'


def test_redirect_chain_keeps_history_cookies_and_final_url(site):
    site.add('/', '', status=302, headers={'Location': '/step', 'Set-Cookie': 'first=1; Path=/'})
    site.add('/step', '', status=301, headers={'Location': site.url + '/final', 'Set-Cookie': 'second=2; Path=/'})
    site.add('/final', page('Done'))

    result = PageFetcher(timeout=5, local_only=True).get(site.url + '/')

    assert result.ok and result.status == 200
    assert result.url == site.url + '/final'
    assert result.redirects == [site.url + '/', site.url + '/step']
    assert result.set_cookies == ['first=1; Path=/', 'second=2; Path=/']
    assert result.describe().startswith(f'GET {site.url}/ -> {site.url}/step -> {site.url}/final -> 200')


def test_localhost_mode_refuses_a_redirect_to_another_host_before_contacting_it(site):
    site.add('/', '', status=302, headers={'Location': '/away', 'Set-Cookie': 'sid=1; Path=/'})
    site.add('/away', '', status=302, headers={'Location': 'http://example.com/'})

    result = PageFetcher(timeout=5, local_only=True).get(site.url + '/')

    assert result.error == 'redirect to example.com blocked: localhost mode only contacts local hosts'
    assert not result.ok and result.status is None
    assert result.redirects == [site.url + '/'] and result.url == site.url + '/away'
    assert result.set_cookies == ['sid=1; Path=/']
    assert result.describe() == f'GET {site.url}/ -> {site.url}/away failed: {result.error}'


def test_redirect_loops_stop_after_ten_hops(site):
    site.add('/loop', '', status=302, headers={'Location': '/loop'})

    result = PageFetcher(timeout=5).get(site.url + '/loop')

    assert result.error == 'too many redirects'
    assert site.hits['/loop'] == 11
