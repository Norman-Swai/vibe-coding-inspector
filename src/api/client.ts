import type { Finding, FixReviewState, ReviewState, ScanRequest, ScanStatusResponse } from '../contracts/finding';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {})
    },
    ...init
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export const apiClient = {
  startScan(payload: ScanRequest) {
    return request<{ scan_id: string }>('/scans', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },
  getScan(scanId: string) {
    return request<ScanStatusResponse>(`/scans/${scanId}`);
  },
  getFindings(scanId: string) {
    return request<Finding[]>(`/scans/${scanId}/findings`);
  },
  updateReview(findingId: string, review: ReviewState) {
    return request<Finding>(`/findings/${findingId}/review`, {
      method: 'PATCH',
      body: JSON.stringify(review)
    });
  },
  updateFixReview(findingId: string, fixReview: FixReviewState) {
    return request<Finding>(`/findings/${findingId}/fix-review`, {
      method: 'PATCH',
      body: JSON.stringify(fixReview)
    });
  },
  async getReport(scanId: string, format: 'json' | 'markdown'): Promise<string> {
    const response = await fetch(`/api/scans/${scanId}/report?format=${format}`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.text();
  }
};
