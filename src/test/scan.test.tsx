import { act, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App from '../App';
import { FindingsPanel } from '../components/FindingsPanel';
import { validateRepoPath, validateTarget } from '../components/LaunchPanel';
import type { Finding } from '../contracts/finding';
import { POLL_INTERVAL_MS, useScan } from '../hooks/useScan';
import { SettingsProvider } from '../lib/settings';
import { installMatchMedia, jsonResponse, makeFinding, makeScan } from './utils';

describe('launch form', () => {
  it('validates the target for the selected mode', () => {
    expect(validateTarget('http://localhost:3000', 'localhost')).toBeNull();
    expect(validateTarget('https://example.com', 'localhost')).toMatch(/Localhost mode only accepts/);
    expect(validateTarget('https://example.com', 'public-readonly')).toBeNull();
    expect(validateTarget('example.com', 'public-readonly')).toMatch(/full URL/);
    expect(validateRepoPath('')).toBeNull();
    expect(validateRepoPath('relative/path')).toMatch(/absolute/);
  });

  it('sends the scan limits from Settings and explains what is missing', async () => {
    window.localStorage.setItem('vci-settings-v1', JSON.stringify({ maxPages: 12, timeoutSeconds: 5 }));
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
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
    expect(fetchMock).not.toHaveBeenCalled();

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

  it('hides the repository field in public mode', async () => {
    window.location.hash = '#/launch';
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('radio', { name: 'Public site' }));
    expect(screen.queryByLabelText('Repository path (optional)')).not.toBeInTheDocument();
  });
});

function renderFindings(findings: Finding[], onUpdated = vi.fn()) {
  return render(
    <SettingsProvider>
      <FindingsPanel scan={makeScan()} findings={findings} onFindingUpdated={onUpdated} />
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

    const reject = screen.getByRole('button', { name: /Reject/ });
    expect(reject).toBeDisabled();
    await user.type(screen.getByLabelText('Reason'), 'Decorative field');
    await user.click(reject);

    expect(JSON.parse(String((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body))).toMatchObject({
      decision: 'rejected',
      reason: 'Decorative field',
      reviewer: 'Norman',
    });
    expect(onUpdated).toHaveBeenCalledWith(updated);
    expect(screen.getByRole('button', { name: 'Approve fix' })).toBeDisabled();
  });

  it('switches between list and detail on narrow screens', async () => {
    installMatchMedia((query) => query === '(max-width: 899px)');
    const user = userEvent.setup();
    renderFindings([makeFinding({ id: 'a', title: 'First' }), makeFinding({ id: 'b', title: 'Second' })]);

    expect(screen.queryByRole('article')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Second/ }));
    expect(screen.getByRole('heading', { name: 'Second' })).toBeInTheDocument();
    // styles.css hides the list pane while data-view="detail" (CSS is not loaded in jsdom).
    expect(screen.getByRole('list', { name: 'Findings' }).closest('.findings-layout')).toHaveAttribute('data-view', 'detail');

    await user.click(screen.getByRole('button', { name: /All findings/ }));
    expect(screen.queryByRole('article')).not.toBeInTheDocument();
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
