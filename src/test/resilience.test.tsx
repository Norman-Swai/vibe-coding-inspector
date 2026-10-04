import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App, { LAST_SCAN_KEY } from '../App';
import { ViewErrorBoundary } from '../components/ViewErrorBoundary';
import { statusIncompatibility } from '../hooks/useScan';
import { jsonResponse, makeFinding, makeScan, mockApi } from './utils';

// The response an older backend (before the views change) returns for GET /api/scans/{id}.
const OLD_STATUS = {
  id: 'old-1',
  target_url: 'http://localhost:8765/',
  repo_path: null,
  inspection_mode: 'localhost',
  created_at: '2026-10-04T04:00:00+00:00',
  module_status: { runtime: 'done', static: 'skipped', security: 'done', compliance: 'done' },
  summary: { total_findings: 3, by_severity: {}, by_category: {} },
};

describe('stale or missing backend', () => {
  it('recognises an older status format', () => {
    expect(statusIncompatibility(makeScan())).toBeNull();
    expect(statusIncompatibility(OLD_STATUS)).toBe('missing status, options, modules, activity_count');
  });

  it('never renders a blank page for a remembered scan from an older backend', async () => {
    window.localStorage.setItem(LAST_SCAN_KEY, 'old-1');
    window.location.hash = '#/launch';
    vi.stubGlobal(
      'fetch',
      vi.fn(
        mockApi({
          '/api/health': () => jsonResponse({ detail: 'Not Found' }, 404),
          '/api/scans/old-1/findings': () => jsonResponse([makeFinding()]),
          '/api/scans/old-1': () => jsonResponse(OLD_STATUS),
        }),
      ),
    );
    render(<App />);

    expect(screen.getByRole('heading', { level: 1, name: 'Launch a scan' })).toBeInTheDocument();
    expect(await screen.findByText(/returned this scan in an older format/)).toBeInTheDocument();
    await waitFor(() => expect(window.localStorage.getItem(LAST_SCAN_KEY)).toBeNull());
    expect(screen.getByText('The inspector API is an older version than this page')).toBeInTheDocument();
    expect(screen.getByText('uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000')).toBeInTheDocument();
  });

  it('blocks scans and explains when the API is outdated', async () => {
    window.location.hash = '#/launch';
    const fetchMock = vi.fn(mockApi({ '/api/health': () => jsonResponse({ detail: 'Not Found' }, 404) }));
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText('The inspector API is an older version than this page');

    await user.click(screen.getByRole('checkbox', { name: /authorised/ }));
    await user.click(screen.getByRole('button', { name: /Start scan/ }));

    expect(screen.getByText(/needs attention first/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.map(([url]) => String(url))).not.toContain('/api/scans');
  });

  it('says when nothing is answering', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    );
    render(<App />);
    expect(await screen.findByText('The inspector API is not reachable')).toBeInTheDocument();
  });

  it('shows no warning when the API is current', async () => {
    vi.stubGlobal('fetch', vi.fn(mockApi({})));
    render(<App />);
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledWith('/api/health', expect.anything()));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});

describe('view error boundary', () => {
  function Broken(): never {
    throw new Error("Cannot read properties of undefined (reading 'runtime')");
  }

  it('replaces a crashed view with a way out instead of a blank page', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const onForgetScan = vi.fn();
    const user = userEvent.setup();
    render(
      <ViewErrorBoundary resetKey="launch|old-1" onForgetScan={onForgetScan}>
        <Broken />
      </ViewErrorBoundary>,
    );
    expect(screen.getByRole('heading', { name: /This view could not be displayed/ })).toBeInTheDocument();
    expect(screen.getByText(/reading 'runtime'/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Forget the current scan' }));
    expect(onForgetScan).toHaveBeenCalled();
  });
});
