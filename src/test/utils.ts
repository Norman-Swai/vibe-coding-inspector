import type { ActivityEvent, Finding, ScanStatusResponse } from '../contracts/finding';

/** jsdom has no matchMedia. Default: light, wide, mouse-driven screen. */
export function installMatchMedia(matches: (query: string) => boolean = () => false) {
  window.matchMedia = (query: string) =>
    ({
      matches: matches(query),
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }) as MediaQueryList;
}

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f1',
    title: 'Form controls have no accessible label',
    category: 'runtime',
    severity: 'medium',
    verification: 'confirmed',
    source_modules: ['runtime'],
    location: { url: 'http://localhost:3000/', line_start: 11, element: '<input name="phone">' },
    evidence: { snippet: '/ L11: <input name="phone">', captured_output: 'GET http://localhost:3000/ -> 200 OK text/html (5 ms)', check: 'Each control needs a label.', occurrences: 1 },
    description_plain: 'Some form fields have no programmatic label.',
    impact_plain: 'Screen-reader users cannot tell what to enter.',
    fix_suggestion: { summary: 'Add a label.' },
    review: { decision: 'pending' },
    fix_review: { decision: 'pending' },
    ...overrides,
  };
}

export function makeScan(overrides: Partial<ScanStatusResponse> = {}): ScanStatusResponse {
  const report = { state: 'done' as const, scanned: 1, scanned_label: '1 page', notes: [], duration_ms: 12 };
  return {
    id: 'scan-1',
    target_url: 'http://localhost:3000/',
    repo_path: null,
    inspection_mode: 'localhost',
    options: { max_pages: 8, timeout_seconds: 10 },
    status: 'completed',
    created_at: '2026-10-04T04:00:00+00:00',
    finished_at: '2026-10-04T04:00:01+00:00',
    module_status: { runtime: 'done', static: 'done', security: 'done', compliance: 'done' },
    modules: { runtime: report, static: report, security: report, compliance: report },
    summary: {
      total_findings: 1,
      by_severity: { critical: 0, high: 0, medium: 1, low: 0, info: 0 },
      by_category: { runtime: 1, static: 0, security: 0, compliance: 0 },
    },
    activity_count: 0,
    last_activity: null,
    ...overrides,
  };
}

export function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

export function makeEvent(overrides: Partial<ActivityEvent> & Pick<ActivityEvent, 'seq'>): ActivityEvent {
  return { at_ms: overrides.seq * 10, module: null, kind: 'step', message: `event ${overrides.seq}`, output: null, request: null, ...overrides };
}

/** Routes fetch() calls to handlers by URL, so tests read like the API they exercise. */
export function mockApi(routes: Record<string, (url: string, init?: RequestInit) => Response | Promise<Response>>) {
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const key = Object.keys(routes)
      .sort((a, b) => b.length - a.length)
      .find((pattern) => url.includes(pattern));
    if (!key) throw new Error(`Unexpected request: ${url}`);
    return routes[key](url, init);
  };
}

export function goTo(hash: string) {
  window.location.hash = hash;
  window.dispatchEvent(new HashChangeEvent('hashchange'));
}
