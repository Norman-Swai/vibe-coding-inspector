import { BarChart3 } from 'lucide-react';
import { activityAsText, ActivityLog, type ActivityUiState, isCommand, parseSource } from '../components/ActivityLog';
import { CoveragePanel } from '../components/CoveragePanel';
import { NetworkTable } from '../components/NetworkTable';
import { scanOutcome } from '../components/ScanMonitor';
import { EmptyState, ErrorNotice, Panel, Tag } from '../components/ui';
import { ViewHeader } from '../components/ViewHeader';
import type { ActivityEvent, ScanStatusResponse } from '../contracts/finding';
import { hrefFor } from '../hooks/useHashRoute';
import { downloadText } from '../lib/download';
import { formatDuration, formatTime, isExpectedMiss } from '../lib/meta';

/** Why the command count can be 0: npm audit is the only command, and the scan records whether it could run. */
export function npmAuditHint(scan: ScanStatusResponse) {
  if (scan.inspection_mode !== 'localhost') return 'npm audit runs only in Localhost mode';
  if (!scan.repo_path) return 'npm audit needs a repository path';
  const note = scan.modules.security.notes.find((text) => text.startsWith('npm audit'));
  if (note) return note.replace(/\.$/, '');
  const state = scan.modules.security.state;
  if (state === 'done') return 'npm audit did not run: the repository has no package.json';
  return state === 'failed' ? 'the security module failed before npm audit ran' : 'npm audit has not run yet';
}

function ScanFacts({ scan, activity }: { scan: ScanStatusResponse; activity: ActivityEvent[] }) {
  const requests = activity.filter((event) => event.request);
  const failedRequests = requests.filter(({ request }) => request && (request.error || ((request.status ?? 0) >= 400 && !isExpectedMiss(request)))).length;
  const count = (kinds: string[]) => activity.filter((event) => kinds.includes(event.kind)).length;
  const duration = scan.finished_at ? new Date(scan.finished_at).getTime() - new Date(scan.created_at).getTime() : null;
  const outcome = scanOutcome(scan);
  const metrics = [
    { label: 'Requests sent', value: requests.length, detail: failedRequests ? `${failedRequests} failed` : 'none failed' },
    { label: 'Checks run', value: count(['check']), detail: 'with recorded results' },
    {
      label: 'Commands run',
      value: activity.filter(isCommand).length,
      detail: activity.some(isCommand) ? 'with captured output' : npmAuditHint(scan),
    },
    { label: 'Warnings & errors', value: count(['warning', 'error']), detail: 'in the activity log' },
  ];
  return (
    <Panel
      title="Scan"
      actions={
        scan.status === 'running' ? (
          <Tag tone="warning">Running</Tag>
        ) : (
          <Tag tone={outcome.tone}>
            {outcome.label} · {formatDuration(duration)}
          </Tag>
        )
      }
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
  source,
  ui,
  onUiChange,
}: {
  scan: ScanStatusResponse | null;
  activity: ActivityEvent[];
  activityDropped: number;
  error: string | null;
  /** From the route (#/analytics?q=…&source=…): what a "Trace in Analytics" link asks to see. */
  query: string;
  source: string | null;
  ui: ActivityUiState;
  onUiChange: (patch: Partial<ActivityUiState>) => void;
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
      <ActivityLog
        events={activity}
        dropped={activityDropped}
        running={scan.status === 'running'}
        ui={ui}
        onUiChange={onUiChange}
        initialQuery={query}
        initialSource={parseSource(source)}
        onDownload={downloadLog}
      />
      <div className="analytics-grid">
        <CoveragePanel scan={scan} />
        <NetworkTable events={activity} baseUrl={scan.target_url} />
      </div>
    </>
  );
}
