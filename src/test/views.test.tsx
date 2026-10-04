import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App, { LAST_SCAN_KEY } from '../App';
import type { ActivityEvent, ScanStatusResponse } from '../contracts/finding';
import { parseHash } from '../hooks/useHashRoute';
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
    expect(screen.getByRole('button', { name: /Scan in progress/ })).toBeDisabled();
    expect(screen.getByRole('status')).toHaveTextContent('1 of 4 modules finished');
    expect(screen.getByText('$ npm audit --json → exit 0, 0 vulnerable packages')).toBeInTheDocument();
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
    expect(trace).toHaveAttribute('href', '#/analytics?q=http%3A%2F%2Flocalhost%3A3000%2F');
    expect(screen.getByRole('heading', { name: 'Artifacts' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Export report' })).toBeInTheDocument();
  });

  it('forgets a scan the backend no longer has', async () => {
    window.localStorage.setItem(LAST_SCAN_KEY, 'gone');
    window.location.hash = '#/findings';
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ detail: 'Scan not found' }, 404)));
    render(<App />);
    await waitFor(() => expect(window.localStorage.getItem(LAST_SCAN_KEY)).toBeNull());
    expect(screen.getByText('No findings yet')).toBeInTheDocument();
  });
});
