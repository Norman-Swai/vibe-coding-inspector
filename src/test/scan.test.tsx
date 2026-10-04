import { act, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App from '../App';
import { EMPTY_FINDINGS_UI, FindingsPanel, type FindingsUiState } from '../components/FindingsPanel';
import { validateRepoPath, validateTarget } from '../components/LaunchPanel';
import type { Finding, ScanStatusResponse } from '../contracts/finding';
import { POLL_INTERVAL_MS, useScan } from '../hooks/useScan';
import { SettingsProvider } from '../lib/settings';
import { HEALTHY, installMatchMedia, jsonResponse, makeFinding, makeScan, mockApi } from './utils';

describe('launch form', () => {
  it('validates the target for the selected mode', () => {
    expect(validateTarget('http://localhost:3000', 'localhost')).toBeNull();
    expect(validateTarget('https://example.com', 'localhost')).toMatch(/Localhost mode only accepts/);
    expect(validateTarget('https://example.com', 'public-readonly')).toBeNull();
    // A value without a scheme gets told what to add, not that its "protocol" is unsupported (new URL parses "localhost:" as one).
    expect(validateTarget('example.com', 'public-readonly')).toMatch(/Add http:\/\/ at the start/);
    expect(validateTarget('localhost:8765', 'localhost')).toMatch(/Add http:\/\/ at the start/);
    expect(validateTarget('ftp://localhost', 'localhost')).toMatch(/Only http:\/\/ and https:\/\//);
    expect(validateTarget('', 'localhost')).toMatch(/full URL/);
    expect(validateRepoPath('')).toBeNull();
    expect(validateRepoPath('relative/path')).toMatch(/absolute/);
  });

  it('sends the scan limits from Settings and explains what is missing', async () => {
    window.localStorage.setItem('vci-settings-v1', JSON.stringify({ maxPages: 12, timeoutSeconds: 5 }));
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === '/api/health') return jsonResponse(HEALTHY);
      if (url === '/api/scans') return jsonResponse({ scan_id: 'scan-1' });
      if (url.endsWith('/findings')) return jsonResponse([makeFinding()]);
      return jsonResponse(makeScan());
    });
    vi.stubGlobal('fetch', fetchMock);
    window.location.hash = '#/launch';
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole('button', { name: /Start scan/ }));
    expect(screen.getByText('Confirm that you are authorised before scanning.')).toBeInTheDocument();
    expect(fetchMock.mock.calls.map(([url]) => String(url))).not.toContain('/api/scans');

    await user.type(screen.getByLabelText('Repository path (optional)'), '/srv/app');
    await user.click(screen.getByRole('checkbox', { name: /authorised/ }));
    await user.click(screen.getByRole('button', { name: /Start scan/ }));

    const [, init] = fetchMock.mock.calls.find(([url]) => url === '/api/scans') as unknown as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({
      target_url: 'http://localhost:3000',
      repo_path: '/srv/app',
      authorization_confirmed: true,
      inspection_mode: 'localhost',
      max_pages: 12,
      timeout_seconds: 5,
    });
    expect(await screen.findByText('Scan complete: 1 finding')).toBeInTheDocument();
    expect(window.localStorage.getItem('vci-last-scan')).toBe('scan-1');
  });

  it('links the authorisation error to the checkbox and moves focus to it', async () => {
    vi.stubGlobal('fetch', vi.fn(mockApi({})));
    window.location.hash = '#/launch';
    const user = userEvent.setup();
    render(<App />);
    const checkbox = screen.getByRole('checkbox', { name: /authorised/ });
    expect(checkbox).not.toHaveAttribute('aria-invalid');

    await user.click(screen.getByRole('button', { name: /Start scan/ }));

    expect(checkbox).toHaveAttribute('aria-invalid', 'true');
    expect(checkbox).toHaveAccessibleDescription('Confirm that you are authorised before scanning.');
    expect(checkbox).toHaveFocus();
    await user.click(checkbox);
    expect(checkbox).not.toHaveAttribute('aria-invalid');
    expect(screen.queryByText('Confirm that you are authorised before scanning.')).not.toBeInTheDocument();
  });

  it('hides the repository field in public mode', async () => {
    window.location.hash = '#/launch';
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('radio', { name: 'Public site' }));
    expect(screen.queryByLabelText('Repository path (optional)')).not.toBeInTheDocument();
  });
});

function FindingsHarness({ findings, scan = makeScan(), onUpdated }: { findings: Finding[]; scan?: ScanStatusResponse; onUpdated: (finding: Finding) => void }) {
  const [ui, setUi] = useState<FindingsUiState>(EMPTY_FINDINGS_UI);
  return <FindingsPanel scan={scan} findings={findings} ui={ui} onUiChange={(patch) => setUi((current) => ({ ...current, ...patch }))} onFindingUpdated={onUpdated} />;
}

function renderFindings(findings: Finding[], onUpdated = vi.fn(), scan?: ScanStatusResponse) {
  return render(
    <SettingsProvider>
      <FindingsHarness findings={findings} scan={scan} onUpdated={onUpdated} />
    </SettingsProvider>,
  );
}

describe('findings', () => {
  it('renders captured evidence as inert text and redacts credential shapes', () => {
    const key = 'AKIA' + 'QWERTYUIOPASDFGH';
    renderFindings([makeFinding({ evidence: { snippet: `<img src=x onerror="alert(1)"> ${key}`, captured_output: 'GET /', check: 'c', occurrences: 1 } })]);
    const evidence = screen.getByLabelText('Evidence excerpt');
    expect(evidence.querySelector('img')).toBeNull();
    expect(evidence.textContent).toContain('<img src=x onerror="alert(1)">');
    expect(evidence.textContent).not.toContain(key);
    expect(evidence.textContent).toContain('AKI••••••');
  });

  it('shows the evidence location, check and source for the selected finding', () => {
    renderFindings([makeFinding()]);
    const detail = screen.getByRole('article');
    expect(within(detail).getByText('/ · line 11')).toBeInTheDocument();
    expect(within(detail).getByText('Each control needs a label.')).toBeInTheDocument();
    expect(within(detail).getByText(/GET http:\/\/localhost:3000\/ -> 200/)).toBeInTheDocument();
  });

  it('filters by severity with counts that match the list', async () => {
    const user = userEvent.setup();
    renderFindings([
      makeFinding({ id: 'a', title: 'Critical one', severity: 'critical' }),
      makeFinding({ id: 'b', title: 'Low one', severity: 'low' }),
      makeFinding({ id: 'c', title: 'Another low', severity: 'low' }),
    ]);
    const list = screen.getByRole('list', { name: 'Findings' });
    expect(within(list).getAllByRole('button')).toHaveLength(3);
    expect(screen.getByRole('button', { name: /^High 0$/ })).toBeDisabled();

    await user.click(screen.getByRole('button', { name: /^Low 2$/ }));
    expect(within(list).getAllByRole('button').map((item) => item.querySelector('.finding-item-title')?.textContent)).toEqual(['Another low', 'Low one']);
  });

  it('requires a reason before rejecting and records the reviewer from Settings', async () => {
    window.localStorage.setItem('vci-settings-v1', JSON.stringify({ reviewer: 'Norman' }));
    const updated = makeFinding({ review: { decision: 'rejected', reason: 'Decorative field', reviewer: 'Norman' } });
    const fetchMock = vi.fn(async () => jsonResponse(updated));
    vi.stubGlobal('fetch', fetchMock);
    const onUpdated = vi.fn();
    const user = userEvent.setup();
    renderFindings([makeFinding()], onUpdated);

    // aria-disabled rather than disabled, so the button keeps keyboard focus; the handler enforces the rule.
    const reject = screen.getByRole('button', { name: /Reject/ });
    expect(reject).toHaveAttribute('aria-disabled', 'true');
    await user.click(reject);
    expect(fetchMock).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText('Reason'), 'Decorative field');
    expect(reject).toHaveAttribute('aria-disabled', 'false');
    await user.click(reject);

    expect(JSON.parse(String((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body))).toMatchObject({
      decision: 'rejected',
      reason: 'Decorative field',
      reviewer: 'Norman',
    });
    expect(onUpdated).toHaveBeenCalledWith(updated);
    const approve = screen.getByRole('button', { name: 'Approve fix' });
    expect(approve).toHaveAttribute('aria-disabled', 'true');
    await user.click(approve);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps keyboard focus on a review button while its request is pending and sends it once', async () => {
    let finish: (response: Response) => void = () => undefined;
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => (finish = resolve)));
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    renderFindings([makeFinding()]);

    const confirm = screen.getByRole('button', { name: /Confirm/ });
    confirm.focus();
    await user.keyboard('{Enter}');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(confirm).toHaveAttribute('aria-disabled', 'true');
    expect(confirm).not.toBeDisabled();
    expect(confirm).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(fetchMock).toHaveBeenCalledTimes(1);

    finish(jsonResponse(makeFinding({ review: { decision: 'confirmed', reviewer: 'Norman', timestamp: '2026-10-04T14:21:00+00:00' } })));
    await waitFor(() => expect(confirm).toHaveAttribute('aria-disabled', 'false'));
    expect(confirm).toHaveFocus();
  });

  it('shows who made the fix decision and when', () => {
    renderFindings([
      makeFinding({
        review: { decision: 'confirmed', reviewer: 'QA Tester', timestamp: '2026-10-04T14:21:00+00:00' },
        fix_review: { decision: 'approved', reviewer: 'QA Tester', timestamp: '2026-10-04T14:22:00+00:00' },
      }),
    ]);
    const detail = screen.getByRole('article');
    const line = within(detail).getByText('Fix decision:').closest('p');
    expect(line).toHaveTextContent(/Approved\s*by QA Tester/);
    expect(line).toHaveTextContent(new Date('2026-10-04T14:22:00+00:00').toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }));
  });

  it('is one tab stop on wide screens: arrow keys move the selection and Tab reaches the detail', async () => {
    const user = userEvent.setup();
    renderFindings([makeFinding({ id: 'a', title: 'First', severity: 'high' }), makeFinding({ id: 'b', title: 'Second' }), makeFinding({ id: 'c', title: 'Third', severity: 'low' })]);
    const list = screen.getByRole('list', { name: 'Findings' });
    const items = within(list).getAllByRole('button');
    expect(items.map((item) => item.tabIndex)).toEqual([0, -1, -1]);

    items[0].focus();
    await user.keyboard('{ArrowDown}');
    expect(items[1]).toHaveFocus();
    expect(screen.getByRole('heading', { level: 3, name: 'Second' })).toBeInTheDocument();
    expect(items.map((item) => item.tabIndex)).toEqual([-1, 0, -1]);
    await user.keyboard('{End}');
    expect(items[2]).toHaveFocus();
    expect(screen.getByRole('heading', { level: 3, name: 'Third' })).toBeInTheDocument();

    await user.tab();
    expect(screen.getByRole('link', { name: /Trace in Analytics/ })).toHaveFocus();
  });

  it('switches between list and detail on narrow screens', async () => {
    installMatchMedia((query) => query === '(max-width: 899px)');
    const user = userEvent.setup();
    renderFindings([makeFinding({ id: 'a', title: 'First' }), makeFinding({ id: 'b', title: 'Second' })]);
    const entries = window.history.length;

    expect(screen.queryByRole('article')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Second/ }));
    const heading = await screen.findByRole('heading', { name: 'Second' });
    // Opening the detail is a navigation of its own, so the system Back button closes it; focus moves into it.
    expect(window.location.hash).toBe('#/findings?finding=b');
    expect(window.history.length).toBe(entries + 1);
    await waitFor(() => expect(heading).toHaveFocus());
    // styles.css hides the list pane while data-view="detail" (CSS is not loaded in jsdom).
    expect(screen.getByRole('list', { name: 'Findings' }).closest('.findings-layout')).toHaveAttribute('data-view', 'detail');

    await user.click(screen.getByRole('button', { name: /All findings/ }));
    await waitFor(() => expect(screen.queryByRole('article')).not.toBeInTheDocument());
    // "All findings" went back to the list entry rather than adding another one.
    expect(window.location.hash).not.toContain('finding=');
    expect(window.history.length).toBe(entries + 1);
    await waitFor(() => expect(screen.getByRole('button', { name: /Second/ })).toHaveFocus());
  });

  it('closes a narrow-screen detail on hardware Back', async () => {
    installMatchMedia((query) => query === '(max-width: 899px)');
    const user = userEvent.setup();
    renderFindings([makeFinding({ id: 'a', title: 'First' })]);
    await user.click(screen.getByRole('button', { name: /First/ }));
    await screen.findByRole('article');

    act(() => window.history.back());
    await waitFor(() => expect(screen.queryByRole('article')).not.toBeInTheDocument());
    expect(screen.getByRole('list', { name: 'Findings' })).toBeInTheDocument();
  });

  it('never reports "No issues found" for modules that did not run', () => {
    const report = { scanned: 0, scanned_label: '', notes: [] };
    const failed = { ...report, state: 'failed' as const, error: 'boom' };
    const skipped = { ...report, state: 'skipped' as const };
    const done = { ...report, state: 'done' as const, scanned: 3, scanned_label: '3 source files' };

    const nothing = renderFindings([], vi.fn(), makeScan({ modules: { runtime: failed, static: skipped, security: failed, compliance: failed } }));
    expect(screen.getByText('Nothing could be checked')).toBeInTheDocument();
    expect(screen.queryByText(/No issues found/)).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'See why in Analytics' })).toHaveAttribute('href', '#/analytics');
    nothing.unmount();

    const partial = renderFindings([], vi.fn(), makeScan({ modules: { runtime: failed, static: done, security: failed, compliance: skipped } }));
    expect(screen.getByText('No issues found by Static code')).toBeInTheDocument();
    expect(screen.getByText(/3 modules did not run/)).toBeInTheDocument();
    partial.unmount();

    renderFindings([], vi.fn(), makeScan());
    expect(screen.getByText('No issues found')).toBeInTheDocument();
    expect(screen.getByText(/Every module ran/)).toBeInTheDocument();
  });
});

describe('polling', () => {
  it('stops once the scan completes and only refetches findings when something changed', async () => {
    vi.useFakeTimers();
    const statuses = [makeScan({ status: 'running', summary: { ...makeScan().summary, total_findings: 0 } }), makeScan(), makeScan()];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith('/findings') ? jsonResponse([makeFinding()]) : jsonResponse(statuses.shift() ?? makeScan()),
    );
    vi.stubGlobal('fetch', fetchMock);

    const { result } = renderHook(() => useScan('scan-1'));
    for (let i = 0; i < 5; i += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
      });
    }
    vi.useRealTimers();

    await waitFor(() => expect(result.current.scan?.status).toBe('completed'));
    const statusCalls = fetchMock.mock.calls.filter(([url]) => !String(url).endsWith('/findings')).length;
    const findingCalls = fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/findings')).length;
    expect(statusCalls).toBe(2);
    expect(findingCalls).toBe(2);
    expect(result.current.findings).toHaveLength(1);
  });
});
