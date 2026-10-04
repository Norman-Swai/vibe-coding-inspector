import type { Finding, FixReviewState, ReviewState, ScanRequest, ScanStatusResponse } from '../contracts/finding';

// The only module that talks to the backend.

type ValidationDetail = { loc?: (string | number)[]; msg?: string };

async function errorMessage(response: Response): Promise<string> {
  const text = await response.text();
  try {
    const body = JSON.parse(text) as { detail?: string | ValidationDetail[] };
    if (typeof body.detail === 'string') return body.detail;
    if (Array.isArray(body.detail)) {
      return body.detail.map((item) => [item.loc?.slice(1).join('.'), item.msg].filter(Boolean).join(': ')).join('; ');
    }
  } catch {
    // Not JSON: fall through to the raw text.
  }
  return text || `Request failed with status ${response.status}`;
}

async function send(path: string, init: RequestInit = {}): Promise<Response> {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: { ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
  });
  if (!response.ok) throw new Error(await errorMessage(response));
  return response;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  return (await send(path, init)).json() as Promise<T>;
}

export type ReportFormat = 'markdown' | 'json';

export const apiClient = {
  startScan(payload: ScanRequest) {
    return json<{ scan_id: string }>('/scans', { method: 'POST', body: JSON.stringify(payload) });
  },
  getScan(scanId: string) {
    return json<ScanStatusResponse>(`/scans/${encodeURIComponent(scanId)}`);
  },
  getFindings(scanId: string) {
    return json<Finding[]>(`/scans/${encodeURIComponent(scanId)}/findings`);
  },
  updateReview(findingId: string, review: ReviewState) {
    return json<Finding>(`/findings/${encodeURIComponent(findingId)}/review`, { method: 'PATCH', body: JSON.stringify(review) });
  },
  updateFixReview(findingId: string, fixReview: FixReviewState) {
    return json<Finding>(`/findings/${encodeURIComponent(findingId)}/fix-review`, { method: 'PATCH', body: JSON.stringify(fixReview) });
  },
  async getReport(scanId: string, format: ReportFormat): Promise<string> {
    return (await send(`/scans/${encodeURIComponent(scanId)}/report?format=${format}`)).text();
  },
};
