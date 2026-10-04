import { act, render, screen, waitFor, within } from '@testing-library/react';
import { StrictMode } from 'react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App, { LAST_SCAN_KEY } from '../App';
import { activityAsText } from '../components/ActivityLog';
import type { ActivityEvent, ModuleReport, ScanStatusResponse } from '../contracts/finding';
import { parseHash } from '../hooks/useHashRoute';
import { npmAuditHint } from '../views/AnalyticsView';
import { goTo, jsonResponse, makeEvent, makeFinding, makeScan, mockApi } from './utils';

const ACTIVITY: ActivityEvent[] = [
  makeEvent({ seq: 1, message: 'Scan started: http://localhost:3000/ (localhost mode)', output: 'max pages: 8' }),
  makeEvent({
    seq: 2,
    kind: 'request',
    message: 'GET http://localhost:3000/ -> 200 OK text/html (5 ms)',
    request: { method: 'GET', url: 'http://localhost:3000/', status: 200, content_type: 'text/html', bytes: 2048, duration_ms: 5 },
  }),
  makeEvent({
    seq: 3,
    kind: 'request',
    message: 'GET http://localhost:3000/docs -> 404 Not Found text/html (2 ms)',
    request: { method: 'GET', url: 'http://localhost:3000/docs', status: 404, content_type: 'text/html', bytes: 90, duration_ms: 2 },
  }),
  makeEvent({ seq: 4, module: 'security', kind: 'check', message: 'Response headers of http://localhost:3000/: 3 issues', output: 'content-security-policy: (not sent)' }),
  makeEvent({ seq: 5, module: 'security', kind: 'command', message: '$ npm audit --json → exit 0, 0 vulnerable packages', output: 'vulnerabilities: {"total": 0}' }),
];

const FAILED_MODULE: ModuleReport = { state: 'failed', scanned: 0, scanned_label: '', notes: [], error: 'connection refused' };
const SKIPPED_MODULE: ModuleReport = { state: 'skipped', scanned: 0, scanned_label: '', notes: [] };

function useCompletedScan(overrides: Partial<ScanStatusResponse> = {}, activity = ACTIVITY) {
  window.localStorage.setItem(LAST_SCAN_KEY, 'scan-1');
  const fetchMock = vi.fn(
    mockApi({
      '/api/scans/scan-1/activity': (url) => {
        const since = Number(new URL(url, 'http://x').searchParams.get('since'));
        const events = activity.filter((event) => event.seq > since);
        return jsonResponse({ events, next_seq: events[events.length - 1]?.seq ?? since, dropped: 0 });
      },
      '/api/scans/scan-1/findings': () => jsonResponse([makeFinding()]),
      '/api/scans/scan-1': () => jsonResponse(makeScan({ activity_count: activity.length, last_activity: activity[activity.length - 1]?.message, ...overrides })),
    }),
  );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

/** A launch whose first status poll already shows the scan complete, after `statusDelayMs` (a real backend is never instant). */
function useInstantScan(statusDelayMs = 0) {
  const fetchMock = vi.fn(
    mockApi({
      '/api/scans/scan-1/activity': () => jsonResponse({ events: [], next_seq: 0, dropped: 0 }),
      '/api/scans/scan-1/findings': () => jsonResponse([makeFinding()]),
      '/api/scans/scan-1': async () => {
        await new Promise((resolve) => setTimeout(resolve, statusDelayMs));
        return jsonResponse(makeScan());
      },
      '/api/scans': () => jsonResponse({ scan_id: 'scan-1' }),
    }),
  );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('routing', () => {
  it('parses view and query from the hash and falls back to Overview', () => {
    expect(parseHash('#/analytics?q=%2Fabout')).toMatchObject({ view: 'analytics' });
    expect(parseHash('#/analytics?q=%2Fabout').params.get('q')).toBe('/about');
    expect(parseHash('#/nope').view).toBe('overview');
    expect(parseHash('').view).toBe('overview');
  });

  it('shows a different view for each navigation item', async () => {
    render(<App />);
    const nav = screen.getByRole('navigation', { name: 'Views' });

    expect(screen.getByRole('heading', { level: 1, name: 'Inspect a web app before you ship it' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'How it works' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Target URL')).not.toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: /Overview/ })).toHaveAttribute('aria-current', 'page');

    act(() => goTo('#/launch'));
    expect(screen.getByRole('heading', { level: 1, name: 'Launch a scan' })).toBeInTheDocument();
    expect(screen.getByLabelText('Target URL')).toBeInTheDocument();
    expect(screen.getByText('Nothing is running')).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: /Launch/ })).toHaveAttribute('aria-current', 'page');

    act(() => goTo('#/analytics'));
    expect(screen.getByRole('heading', { level: 1, name: 'Analytics' })).toBeInTheDocument();
    expect(screen.getByText('No scan to analyse yet')).toBeInTheDocument();
    expect(screen.queryByLabelText('Target URL')).not.toBeInTheDocument();

    act(() => goTo('#/findings'));
    expect(screen.getByRole('heading', { level: 1, name: 'Findings' })).toBeInTheDocument();
    expect(screen.getByText('No findings yet')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('heading', { level: 1 })).toHaveFocus());
  });
});

describe('launch form', () => {
  it('keeps what was typed when switching views', async () => {
    window.location.hash = '#/launch';
    const user = userEvent.setup();
    render(<App />);
    await user.clear(screen.getByLabelText('Target URL'));
    await user.type(screen.getByLabelText('Target URL'), 'http://localhost:4000');
    await user.type(screen.getByLabelText('Repository path (optional)'), '/srv/app');
    await user.click(screen.getByRole('checkbox', { name: /authorised/ }));

    act(() => goTo('#/overview'));
    act(() => goTo('#/launch'));

    expect(screen.getByLabelText('Target URL')).toHaveValue('http://localhost:4000');
    expect(screen.getByLabelText('Repository path (optional)')).toHaveValue('/srv/app');
    expect(screen.getByRole('checkbox', { name: /authorised/ })).toBeChecked();
  });

  it('keeps what was typed across a reload', async () => {
    window.location.hash = '#/launch';
    const user = userEvent.setup();
    const first = render(<App />);
    await user.click(screen.getByRole('radio', { name: 'Public site' }));
    await user.clear(screen.getByLabelText('Target URL'));
    await user.type(screen.getByLabelText('Target URL'), 'https://example.com/');
    await user.click(screen.getByRole('checkbox', { name: /authorised/ }));
    first.unmount();

    // A reload is a fresh component tree with the same sessionStorage.
    render(<App />);
    expect(screen.getByRole('radio', { name: 'Public site' })).toBeChecked();
    expect(screen.getByLabelText('Target URL')).toHaveValue('https://example.com/');
    expect(screen.getByRole('checkbox', { name: /authorised/ })).toBeChecked();
    expect(screen.getByText(/progress appears in Scan status/)).toBeInTheDocument();
  });

  it('shows a rejected start on the field it names and clears it once that field is edited', async () => {
    vi.stubGlobal('fetch', vi.fn(mockApi({ '/api/scans': () => jsonResponse({ detail: 'Repository path is not a directory: /srv/app/README.md' }, 400) })));
    window.location.hash = '#/launch';
    const user = userEvent.setup();
    render(<App />);
    const repo = screen.getByLabelText('Repository path (optional)');
    await user.type(repo, '/srv/app/README.md');
    await user.click(screen.getByRole('checkbox', { name: /authorised/ }));
    await user.click(screen.getByRole('button', { name: /Start scan/ }));

    await screen.findByText('Repository path is not a directory: /srv/app/README.md');
    expect(repo).toHaveAttribute('aria-invalid', 'true');
    expect(repo).toHaveAccessibleDescription(/not a directory/);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    await user.type(repo, '{Backspace}');
    expect(screen.queryByText(/not a directory/)).not.toBeInTheDocument();
    expect(repo).not.toHaveAttribute('aria-invalid');
  });

  it('scrolls the live monitor into view only once the started scan has rendered', async () => {
    // The status arrives later than the first animation frame, as it does with a real backend.
    useInstantScan(80);
    window.location.hash = '#/launch';
    // A stacked layout: the monitor panel sits far below the fold.
    vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({ top: 1000, bottom: 1500, left: 0, right: 375, width: 375, height: 500, x: 0, y: 1000, toJSON: () => ({}) });
    const scrolled: string[] = [];
    vi.spyOn(Element.prototype, 'scrollIntoView').mockImplementation(function scrollIntoView(this: Element) {
      scrolled.push(`${this.className}: ${this.textContent ?? ''}`);
    });
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('checkbox', { name: /authorised/ }));
    await user.click(screen.getByRole('button', { name: /Start scan/ }));

    await screen.findByText('Scan complete: 1 finding');
    await waitFor(() => expect(scrolled.some((entry) => entry.includes('monitor-panel'))).toBe(true));
    const [first] = scrolled.filter((entry) => entry.includes('monitor-panel'));
    expect(first).toContain('Scan complete');
    expect(first).not.toContain('Nothing is running');
  });
});

describe('scanning indicator', () => {
  it('is visible from every view while a scan runs', async () => {
    useCompletedScan({
      status: 'running',
      finished_at: null,
      module_status: { runtime: 'running', static: 'done', security: 'running', compliance: 'queued' },
      modules: {
        runtime: { state: 'running', scanned: 0, scanned_label: '', notes: [] },
        static: { state: 'done', scanned: 1, scanned_label: '1 source file', notes: [], duration_ms: 4 },
        security: { state: 'running', scanned: 0, scanned_label: '', notes: [] },
        compliance: { state: 'queued', scanned: 0, scanned_label: '', notes: [] },
      },
    });
    render(<App />);

    expect(await screen.findByRole('link', { name: /Scanning 1\/4/ })).toHaveAttribute('href', '#/launch');
    expect(document.title).toMatch(/^Scanning…/);

    act(() => goTo('#/launch'));
    // aria-disabled rather than disabled, so a keyboard user's focus stays on the button.
    expect(screen.getByRole('button', { name: /Scan in progress/ })).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByText(/1 of 4 modules finished/)).toBeInTheDocument();
    expect(screen.getByText('$ npm audit --json → exit 0, 0 vulnerable packages')).toBeInTheDocument();
  });

  it('keeps the whole current step reachable through its title, since phones clamp the line', async () => {
    window.location.hash = '#/launch';
    const step = 'Parsed /privacy: 0 links, 0 new same-origin URLs queued ?token=abcdef123456';
    useCompletedScan({ status: 'running', finished_at: null, last_activity: step });
    render(<App />);
    const now = await screen.findByText(/Parsed \/privacy/);
    expect(now).toHaveAttribute('title', now.textContent);
    expect(now.textContent).not.toContain('abcdef123456');
  });
});

describe('announcements and focus', () => {
  it('announces the end of a scan from any view through one live region', async () => {
    let status: Partial<ScanStatusResponse> = { status: 'running', finished_at: null };
    window.localStorage.setItem(LAST_SCAN_KEY, 'scan-1');
    vi.stubGlobal(
      'fetch',
      vi.fn(
        mockApi({
          '/api/scans/scan-1/activity': () => jsonResponse({ events: [], next_seq: 0, dropped: 0 }),
          '/api/scans/scan-1/findings': () => jsonResponse([makeFinding()]),
          '/api/scans/scan-1': () => jsonResponse(makeScan(status)),
        }),
      ),
    );
    render(<App />);
    const live = screen.getByRole('status');
    await screen.findByRole('link', { name: /Scanning/ });
    expect(live).toHaveTextContent('');
    status = {};
    expect(await screen.findByText('Scan complete: 1 finding.')).toBe(live);
  });

  it('announces the end of a scan started here even when its first poll already shows it complete', async () => {
    useInstantScan();
    window.location.hash = '#/launch';
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('checkbox', { name: /authorised/ }));
    await user.click(screen.getByRole('button', { name: /Start scan/ }));
    expect(await screen.findByText('Scan complete: 1 finding.')).toBe(screen.getByRole('status'));
  });

  it('does not re-announce a finished scan restored on reload', async () => {
    window.location.hash = '#/launch';
    useCompletedScan();
    render(<App />);
    await screen.findByText('Scan complete: 1 finding');
    expect(screen.getByRole('status')).toHaveTextContent('');
  });

  it('keeps the live region outside the inert app while the settings drawer is open', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: 'Settings' }));
    expect(screen.getByRole('dialog', { name: 'Settings' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1 }).closest('[inert]')).not.toBeNull();
    expect(screen.getByRole('status').closest('[inert]')).toBeNull();
  });

  it('does not move focus on first load, even when effects run twice (StrictMode)', () => {
    window.location.hash = '#/findings';
    render(
      <StrictMode>
        <App />
      </StrictMode>,
    );
    expect(document.body).toHaveFocus();
  });
});

describe('analytics', () => {
  it('shows what was done: requests, checks and command output', async () => {
    window.location.hash = '#/analytics';
    useCompletedScan();
    const user = userEvent.setup();
    render(<App />);

    const log = await screen.findByRole('list', { name: 'Activity log' });
    expect(within(log).getAllByRole('listitem')).toHaveLength(5);
    expect(within(log).getByText('vulnerabilities: {"total": 0}')).toBeVisible();
    expect(screen.getByRole('cell', { name: /GET \/docs/ })).toBeInTheDocument();
    expect(screen.getByText(/2 requests · 1 failed/)).toBeInTheDocument();

    await user.click(screen.getByRole('radio', { name: 'Commands' }));
    expect(within(log).getAllByRole('listitem')).toHaveLength(1);
    await user.click(screen.getByRole('radio', { name: 'Requests' }));
    expect(within(log).getAllByRole('listitem')).toHaveLength(2);
  });

  it('opens pre-filtered when a finding is traced', async () => {
    window.location.hash = '#/analytics?q=%2Fdocs';
    useCompletedScan();
    render(<App />);
    const log = await screen.findByRole('list', { name: 'Activity log' });
    expect(screen.getByLabelText('Search activity')).toHaveValue('/docs');
    expect(within(log).getAllByRole('listitem')).toHaveLength(1);
  });

  it('matches a traced page URL whole, within the finding module and the shared work', async () => {
    window.location.hash = '#/analytics?q=http%3A%2F%2Flocalhost%3A3000%2F&source=runtime';
    useCompletedScan();
    const user = userEvent.setup();
    render(<App />);
    const log = await screen.findByRole('list', { name: 'Activity log' });
    expect(screen.getByLabelText('Source')).toHaveValue('runtime');
    // The request for that page and the scan start, not /docs and not the security module's check of the same page.
    expect(within(log).getAllByRole('listitem').map((item) => item.querySelector('.break-anywhere')?.textContent)).toEqual([
      'Scan started: http://localhost:3000/ (localhost mode)',
      'GET http://localhost:3000/ -> 200 OK text/html (5 ms)',
    ]);
    await user.selectOptions(screen.getByLabelText('Source'), 'all');
    expect(within(log).getAllByRole('listitem')).toHaveLength(3);
  });

  it('keeps the activity filters when leaving Analytics and coming back', async () => {
    window.location.hash = '#/analytics';
    useCompletedScan();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole('list', { name: 'Activity log' });
    await user.click(screen.getByRole('radio', { name: 'Checks' }));
    await user.selectOptions(screen.getByLabelText('Source'), 'security');
    await user.type(screen.getByLabelText('Search activity'), 'headers');
    expect(screen.getByText('Showing 1 of 5 events')).toBeInTheDocument();

    act(() => goTo('#/overview'));
    act(() => goTo('#/analytics'));

    expect(screen.getByText('Showing 1 of 5 events')).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: 'Checks' })).toBeChecked();
    expect(screen.getByLabelText('Source')).toHaveValue('security');
    expect(screen.getByLabelText('Search activity')).toHaveValue('headers');
  });

  it('explains why there are no commands instead of a generic empty filter', async () => {
    window.location.hash = '#/analytics';
    useCompletedScan({}, ACTIVITY.slice(0, 4));
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole('list', { name: 'Activity log' });
    await user.click(screen.getByRole('radio', { name: 'Commands' }));
    expect(screen.getByText('No commands were run in this scan')).toBeInTheDocument();
    // The hint comes from the scan itself (no repository was given), not a fixed sentence.
    expect(screen.getByText('npm audit needs a repository path')).toBeInTheDocument();
  });

  it('derives the npm audit hint from the scan', () => {
    expect(npmAuditHint(makeScan({ inspection_mode: 'public-readonly' }))).toBe('npm audit runs only in Localhost mode');
    expect(npmAuditHint(makeScan({ repo_path: '/srv/app' }))).toBe('npm audit did not run: the repository has no package.json');
    const note = 'npm audit skipped: package.json has no package-lock.json, so installed versions are unknown.';
    const security: ModuleReport = { ...makeScan().modules.security, notes: [note] };
    expect(npmAuditHint(makeScan({ repo_path: '/srv/app', modules: { ...makeScan().modules, security } }))).toBe(note.slice(0, -1));
  });

  it('does not call a scan with failed or skipped modules completed, and names every module that did not run', async () => {
    window.location.hash = '#/analytics';
    const errors = useCompletedScan({
      module_status: { runtime: 'failed', static: 'skipped', security: 'failed', compliance: 'failed' },
      modules: { runtime: FAILED_MODULE, static: SKIPPED_MODULE, security: FAILED_MODULE, compliance: FAILED_MODULE },
      summary: { ...makeScan().summary, total_findings: 0 },
    });
    const first = render(<App />);
    const scan = await screen.findByRole('region', { name: 'Scan' });
    expect(within(scan).getByText(/Finished with errors/)).toHaveAttribute('data-tone', 'danger');
    expect(within(scan).queryByText(/Completed/)).not.toBeInTheDocument();
    act(() => goTo('#/findings'));
    expect(await screen.findByText(/Runtime, Static code, Security, and Compliance were skipped or failed/)).toBeInTheDocument();
    first.unmount();
    errors.mockClear();

    window.location.hash = '#/analytics';
    useCompletedScan({
      module_status: { runtime: 'skipped', static: 'skipped', security: 'skipped', compliance: 'skipped' },
      modules: { runtime: SKIPPED_MODULE, static: SKIPPED_MODULE, security: SKIPPED_MODULE, compliance: SKIPPED_MODULE },
    });
    render(<App />);
    const skipped = await screen.findByRole('region', { name: 'Scan' });
    expect(within(skipped).getByText(/Finished, nothing checked/)).toHaveAttribute('data-tone', 'warning');
  });

  it('does not count the expected robots.txt miss as a failed request', async () => {
    window.location.hash = '#/analytics';
    const robots = makeEvent({
      seq: 6,
      kind: 'request',
      message: 'GET http://localhost:3000/robots.txt -> 404 Not Found (1 ms)',
      request: { method: 'GET', url: 'http://localhost:3000/robots.txt', status: 404, duration_ms: 1 },
    });
    useCompletedScan({}, [ACTIVITY[0], ACTIVITY[1], robots]);
    render(<App />);
    const scan = await screen.findByRole('region', { name: 'Scan' });
    expect(within(scan).getByText('2')).toBeInTheDocument();
    expect(within(scan).getByText('none failed')).toBeInTheDocument();
  });

  it('counts a failed command as a command and a problem', async () => {
    window.location.hash = '#/analytics';
    const failed = makeEvent({ seq: 6, module: 'security', kind: 'error', message: '$ npm audit --json → exit 1, audit failed: offline', output: 'offline' });
    useCompletedScan({}, [...ACTIVITY.slice(0, 4), failed]);
    const user = userEvent.setup();
    render(<App />);
    const log = await screen.findByRole('list', { name: 'Activity log' });
    await user.click(screen.getByRole('radio', { name: 'Commands' }));
    expect(within(log).getAllByRole('listitem')).toHaveLength(1);
    await user.click(screen.getByRole('radio', { name: 'Problems' }));
    expect(within(log).getAllByRole('listitem')).toHaveLength(1);
  });

  it('masks credential-shaped values in every place activity text is shown', async () => {
    window.location.hash = '#/analytics';
    // Split so the fixture itself never looks like a key to a secret scanner.
    const key = 'AIza' + 'SyA1234567890abcdefghijklmnopqrstuv';
    const leaky = makeEvent({
      seq: 6,
      kind: 'request',
      message: `GET http://localhost:3000/maps?key=${key} -> 200 OK`,
      request: { method: 'GET', url: 'http://localhost:3000/maps?access_token=abcdef123456', status: 200 },
    });
    useCompletedScan({}, [...ACTIVITY, leaky]);
    render(<App />);
    await screen.findByRole('list', { name: 'Activity log' });
    expect(document.body.textContent).not.toContain(key);
    expect(document.body.textContent).not.toContain('abcdef123456');
    expect(activityAsText([leaky])).not.toContain(key.slice(0, 17));
  });

  it('fetches only new activity events', async () => {
    window.location.hash = '#/analytics';
    const fetchMock = useCompletedScan();
    render(<App />);
    await screen.findByRole('list', { name: 'Activity log' });
    const activityCalls = fetchMock.mock.calls.map(([url]) => String(url)).filter((url) => url.includes('/activity'));
    expect(activityCalls).toEqual(['/api/scans/scan-1/activity?since=0']);
  });
});

describe('findings view', () => {
  it('summarises observations and links each artifact to the activity that produced it', async () => {
    window.location.hash = '#/findings';
    useCompletedScan();
    render(<App />);

    const summary = await screen.findByRole('region', { name: 'Summary' });
    expect(within(summary).getByText('1 observed directly · 0 hypotheses to confirm')).toBeInTheDocument();
    expect(within(summary).getByText('0/1')).toBeInTheDocument();
    const trace = await screen.findByRole('link', { name: /Trace in Analytics/ });
    // The page URL plus the finding's module, so Analytics shows the request for that page rather than every request.
    expect(trace).toHaveAttribute('href', '#/analytics?q=http%3A%2F%2Flocalhost%3A3000%2F&source=runtime');
    expect(screen.getByRole('heading', { name: 'Artifacts' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Export report' })).toBeInTheDocument();
  });

  it('traces a header finding to the check that produced it', async () => {
    window.location.hash = '#/findings';
    window.localStorage.setItem(LAST_SCAN_KEY, 'scan-1');
    const csp = makeFinding({
      id: 'csp',
      title: 'Missing Content-Security-Policy header',
      category: 'security',
      source_modules: ['security'],
      location: { url: 'http://localhost:3000/', element: 'response headers' },
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(
        mockApi({
          '/api/scans/scan-1/activity': () => jsonResponse({ events: ACTIVITY, next_seq: ACTIVITY.length, dropped: 0 }),
          '/api/scans/scan-1/findings': () => jsonResponse([csp]),
          '/api/scans/scan-1': () => jsonResponse(makeScan({ activity_count: ACTIVITY.length })),
        }),
      ),
    );
    render(<App />);
    const trace = await screen.findByRole('link', { name: /Trace in Analytics/ });
    expect(trace).toHaveAttribute('href', '#/analytics?q=Response+headers+of+http%3A%2F%2Flocalhost%3A3000%2F&source=security');

    act(() => goTo(trace.getAttribute('href')!));
    const log = await screen.findByRole('list', { name: 'Activity log' });
    expect(within(log).getAllByRole('listitem')).toHaveLength(1);
    expect(within(log).getByText('Response headers of http://localhost:3000/: 3 issues')).toBeInTheDocument();
    expect(screen.getByLabelText('Source')).toHaveValue('security');
    expect(screen.getByText('Showing 1 of 5 events')).toBeInTheDocument();
  });

  it('forgets a scan the backend no longer has', async () => {
    window.localStorage.setItem(LAST_SCAN_KEY, 'gone');
    window.location.hash = '#/findings';
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ detail: 'Scan not found' }, 404)));
    render(<App />);
    await waitFor(() => expect(window.localStorage.getItem(LAST_SCAN_KEY)).toBeNull());
    expect(screen.getByText('No findings yet')).toBeInTheDocument();
    // The reason stays on screen after the scan id is cleared (it used to be wiped in the same render).
    expect(await screen.findByText(/previous scan is no longer available/)).toBeInTheDocument();
    act(() => goTo('#/launch'));
    expect(screen.getByText(/previous scan is no longer available/)).toBeInTheDocument();
  });

  function useTwoFindings() {
    window.localStorage.setItem(LAST_SCAN_KEY, 'scan-1');
    vi.stubGlobal(
      'fetch',
      vi.fn(
        mockApi({
          '/api/scans/scan-1/activity': () => jsonResponse({ events: ACTIVITY, next_seq: ACTIVITY.length, dropped: 0 }),
          '/api/scans/scan-1/findings': () =>
            jsonResponse([
              makeFinding({ id: 'a', title: 'First finding', severity: 'high' }),
              makeFinding({ id: 'b', title: 'Second finding', severity: 'low', location: { file: 'app.js', line_start: 2 } }),
            ]),
          '/api/scans/scan-1': () => jsonResponse(makeScan({ activity_count: ACTIVITY.length, summary: { ...makeScan().summary, total_findings: 2 } })),
        }),
      ),
    );
  }

  it('keeps the selected finding and filters after tracing to Analytics and going back', async () => {
    window.location.hash = '#/findings';
    useTwoFindings();
    const user = userEvent.setup();
    render(<App />);
    await user.type(await screen.findByLabelText('Search findings'), 'finding');
    await user.click(screen.getByRole('button', { name: /Second finding/ }));
    expect(screen.getByRole('heading', { level: 3, name: 'Second finding' })).toBeInTheDocument();

    act(() => goTo('#/analytics?q=app.js'));
    expect(screen.getByRole('heading', { level: 1, name: 'Analytics' })).toBeInTheDocument();
    act(() => goTo('#/findings'));

    expect(screen.getByLabelText('Search findings')).toHaveValue('finding');
    expect(screen.getByRole('heading', { level: 3, name: 'Second finding' })).toBeInTheDocument();
  });

  it('keeps the selected finding and filters across a reload of the same scan', async () => {
    window.location.hash = '#/findings';
    useTwoFindings();
    const user = userEvent.setup();
    const first = render(<App />);
    await user.click(await screen.findByRole('button', { name: /^Low 1$/ }));
    await user.click(screen.getByRole('button', { name: /Second finding/ }));
    expect(screen.getByRole('heading', { level: 3, name: 'Second finding' })).toBeInTheDocument();
    first.unmount();

    render(<App />);
    expect(await screen.findByRole('button', { name: /^Low 1$/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('heading', { level: 3, name: 'Second finding' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /First finding/ })).not.toBeInTheDocument();
  });
});
