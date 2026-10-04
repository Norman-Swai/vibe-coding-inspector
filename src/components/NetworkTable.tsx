import { Globe } from 'lucide-react';
import type { ActivityEvent } from '../contracts/finding';
import { formatBytes, formatDuration } from '../lib/meta';
import { EmptyState, Panel } from './ui';

function shortUrl(url: string, base: string) {
  try {
    const parsed = new URL(url);
    return parsed.origin === new URL(base).origin ? `${parsed.pathname}${parsed.search}` : url;
  } catch {
    return url;
  }
}

function statusTone(status?: number | null, error?: string | null) {
  if (error || status == null) return 'danger';
  if (status >= 500) return 'danger';
  if (status >= 400) return 'warning';
  return 'success';
}

/** Every HTTP request the scan sent, from the activity log. Rows become cards on narrow screens. */
export function NetworkTable({ events, baseUrl }: { events: ActivityEvent[]; baseUrl: string }) {
  const requests = events.filter((event) => event.request).map((event) => event.request!);
  const failed = requests.filter((request) => request.error || (request.status ?? 0) >= 400).length;
  const totalBytes = requests.reduce((sum, request) => sum + (request.bytes ?? 0), 0);
  const average = requests.length ? Math.round(requests.reduce((sum, request) => sum + (request.duration_ms ?? 0), 0) / requests.length) : 0;

  return (
    <Panel title="Network" description="HTTP requests sent by the crawler and checks. Each URL is fetched once per scan." className="network-panel">
      {requests.length === 0 ? (
        <EmptyState icon={Globe} title="No requests yet" />
      ) : (
        <>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">URL</th>
                  <th scope="col">Type</th>
                  <th scope="col" className="numeric">
                    Size
                  </th>
                  <th scope="col" className="numeric">
                    Time
                  </th>
                </tr>
              </thead>
              <tbody>
                {requests.map((request, index) => (
                  <tr key={`${request.url}-${index}`}>
                    <td data-label="Status">
                      <span className="badge" data-tone={statusTone(request.status, request.error)}>
                        {request.error ? 'failed' : request.status}
                      </span>
                    </td>
                    <td data-label="URL" className="break-anywhere mono">
                      {request.method} {shortUrl(request.url, baseUrl)}
                      {request.final_url && <span className="muted"> → {shortUrl(request.final_url, baseUrl)}</span>}
                      {request.error && <span className="field-error"> {request.error}</span>}
                    </td>
                    <td data-label="Type">{request.content_type ?? '—'}</td>
                    <td data-label="Size" className="numeric">
                      {formatBytes(request.bytes)}
                    </td>
                    <td data-label="Time" className="numeric">
                      {formatDuration(request.duration_ms)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted small list-footer">
            {requests.length} request{requests.length === 1 ? '' : 's'} · {failed} failed · {formatBytes(totalBytes)} downloaded · {average} ms average
          </p>
        </>
      )}
    </Panel>
  );
}
