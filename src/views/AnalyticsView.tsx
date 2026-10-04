import { BarChart3 } from 'lucide-react';
import { activityAsText, ActivityLog } from '../components/ActivityLog';
import { CoveragePanel } from '../components/CoveragePanel';
import { NetworkTable } from '../components/NetworkTable';
import { EmptyState, ErrorNotice, Panel, Tag } from '../components/ui';
import { ViewHeader } from '../components/ViewHeader';
import type { ActivityEvent, ScanStatusResponse } from '../contracts/finding';
import { hrefFor } from '../hooks/useHashRoute';
import { downloadText } from '../lib/download';
import { formatDuration, formatTime } from '../lib/meta';

function ScanFacts({ scan, activity }: { scan: ScanStatusResponse; activity: ActivityEvent[] }) {
  const requests = activity.filter((event) => event.request);
  const failedRequests = requests.filter((event) => event.request?.error || (event.request?.status ?? 0) >= 400).length;
  const count = (kinds: string[]) => activity.filter((event) => kinds.includes(event.kind)).length;
  const duration = scan.finished_at ? new Date(scan.finished_at).getTime() - new Date(scan.created_at).getTime() : null;
  const metrics = [
    { label: 'Requests sent', value: requests.length, detail: failedRequests ? `${failedRequests} failed` : 'none failed' },
    { label: 'Checks run', value: count(['check']), detail: 'with recorded results' },
    { label: 'Commands run', value: count(['command']), detail: 'with captured output' },
    { label: 'Warnings & errors', value: count(['warning', 'error']), detail: 'in the activity log' },
  ];
  return (
    <Panel
      title="Scan"
      actions={scan.status === 'running' ? <Tag tone="warning">Running</Tag> : <Tag tone="success">Completed in {formatDuration(duration)}</Tag>}
    >
      <dl className="facts facts-wide">
        <div>
          <dt>Target</dt>
          <dd className="break-anywhere">{scan.target_url}</dd>
        </div>
        <div>
          <dt>Mode</dt>
          <dd>{scan.inspection_mode === 'localhost' ? 'Localhost (authorised)' : 'Public site (read-only)'}</dd>
        </div>
        <div>
          <dt>Repository</dt>
          <dd className="break-anywhere">{scan.repo_path ?? 'Not provided'}</dd>
        </div>
        <div>
          <dt>Limits</dt>
          <dd>
            {scan.options.max_pages} pages · {scan.options.timeout_seconds} s timeout
          </dd>
        </div>
        <div>
          <dt>Started</dt>
          <dd>{formatTime(scan.created_at)}</dd>
        </div>
      </dl>
      <ul className="metric-grid" role="list">
        {metrics.map((metric) => (
          <li key={metric.label} className="metric">
            <span className="metric-value">{metric.value}</span>
            <span className="metric-label">{metric.label}</span>
            <span className="muted small">{metric.detail}</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export function AnalyticsView({
  scan,
  activity,
  activityDropped,
  error,
  query,
}: {
  scan: ScanStatusResponse | null;
  activity: ActivityEvent[];
  activityDropped: number;
  error: string | null;
  query: string;
}) {
  const header = <ViewHeader title="Analytics" description="What the inspector actually did: every request, check and command, with its output, and what each module covered." />;
  if (!scan) {
    return (
      <>
        {header}
        {error && <ErrorNotice>{error}</ErrorNotice>}
        <EmptyState icon={BarChart3} title="No scan to analyse yet">
          <a href={hrefFor('launch')}>Launch a scan</a> and its activity will stream in here live.
        </EmptyState>
      </>
    );
  }

  function downloadLog() {
    if (!scan) return;
    const head = [`Vibe Coding Inspector activity log`, `Scan ${scan.id}`, `Target ${scan.target_url} (${scan.inspection_mode})`, `Started ${scan.created_at}`, ''];
    downloadText(`${head.join('\n')}${activityAsText(activity)}\n`, 'text/plain', scan, 'activity', 'log');
  }

  return (
    <>
      {header}
      {error && <ErrorNotice>{error}</ErrorNotice>}
      <ScanFacts scan={scan} activity={activity} />
      <ActivityLog events={activity} dropped={activityDropped} running={scan.status === 'running'} initialQuery={query} onDownload={downloadLog} />
      <div className="analytics-grid">
        <CoveragePanel scan={scan} />
        <NetworkTable events={activity} baseUrl={scan.target_url} />
      </div>
    </>
  );
}
