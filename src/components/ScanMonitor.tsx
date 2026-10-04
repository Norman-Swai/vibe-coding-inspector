import { Activity as ActivityIcon, ArrowRight, Radar } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { ScanStatusResponse } from '../contracts/finding';
import { hrefFor } from '../hooks/useHashRoute';
import { formatDuration, MODULE_META, MODULES, redactSecrets } from '../lib/meta';
import { EmptyState, ErrorNotice, Panel, StateBadge, Tag } from './ui';

const TERMINAL = ['done', 'failed', 'skipped'];

export function finishedModules(scan: ScanStatusResponse) {
  return MODULES.filter((module) => TERMINAL.includes(scan.modules[module].state)).length;
}

/** How a finished scan ended. Every status badge uses these words, and none is green unless something was actually checked. */
export function scanOutcome(scan: ScanStatusResponse): { tone: 'success' | 'warning' | 'danger'; label: string } {
  const states = MODULES.map((module) => scan.modules[module].state);
  if (states.includes('failed')) return { tone: 'danger', label: 'Finished with errors' };
  if (!states.includes('done')) return { tone: 'warning', label: 'Finished, nothing checked' };
  return { tone: 'success', label: 'Complete' };
}

/** Elapsed time that ticks while the scan runs. Uses the local start time when known (no clock skew). */
function useElapsed(scan: ScanStatusResponse | null, localStart: number | null) {
  const running = scan?.status === 'running';
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(timer);
  }, [running]);
  if (!scan) return null;
  const serverStart = new Date(scan.created_at).getTime();
  if (!running) return scan.finished_at ? new Date(scan.finished_at).getTime() - serverStart : null;
  return Math.max(0, now - (localStart ?? serverStart));
}

/** Live view of the current scan, shown next to the launch form. */
export function ScanMonitor({
  scan,
  error,
  findingsCount,
  localStart,
}: {
  scan: ScanStatusResponse | null;
  error: string | null;
  findingsCount: number;
  localStart: number | null;
}) {
  const elapsed = useElapsed(scan, localStart);

  if (!scan) {
    return (
      <Panel title="Scan status" className="monitor-panel">
        {error ? (
          <ErrorNotice>{error}</ErrorNotice>
        ) : (
          <EmptyState icon={Radar} title="Nothing is running">
            Fill in the form and start a scan. Its progress will appear here, module by module.
          </EmptyState>
        )}
      </Panel>
    );
  }

  const running = scan.status === 'running';
  const finished = finishedModules(scan);
  const failed = MODULES.filter((module) => scan.modules[module].state === 'failed');
  const outcome = scanOutcome(scan);

  return (
    <Panel
      title="Scan status"
      className="monitor-panel"
      description={<span className="break-anywhere">{scan.target_url}</span>}
      actions={
        running ? (
          <Tag tone="warning">
            <span className="spinner" aria-hidden="true" /> Scanning · {formatDuration(elapsed)}
          </Tag>
        ) : (
          <Tag tone={outcome.tone}>
            {outcome.label} · {formatDuration(elapsed)}
          </Tag>
        )
      }
    >
      <div className="progress" data-running={running || undefined} role="progressbar" aria-label="Modules finished" aria-valuemin={0} aria-valuemax={MODULES.length} aria-valuenow={finished}>
        <span style={{ width: `${Math.max(running ? 6 : 0, (finished / MODULES.length) * 100)}%` }} />
      </div>
      <p className="monitor-summary">
        {running
          ? `${finished} of ${MODULES.length} modules finished · ${findingsCount} finding${findingsCount === 1 ? '' : 's'} so far`
          : `Scan complete: ${findingsCount} finding${findingsCount === 1 ? '' : 's'}${failed.length ? `, ${failed.length} module${failed.length === 1 ? '' : 's'} failed` : ''}`}
      </p>

      <ul className="monitor-modules" role="list">
        {MODULES.map((module) => {
          const report = scan.modules[module];
          const { icon: Icon, label } = MODULE_META[module];
          return (
            <li key={module} data-state={report.state}>
              <Icon size={16} aria-hidden="true" />
              <span className="monitor-module-name">{label}</span>
              <span className="muted small">{report.duration_ms != null ? formatDuration(report.duration_ms) : ''}</span>
              <StateBadge state={report.state} />
            </li>
          );
        })}
      </ul>

      {running && scan.last_activity && (
        <p className="monitor-now">
          <ActivityIcon size={14} aria-hidden="true" />
          <span className="visually-hidden">Currently: </span>
          <span className="monitor-now-text">{redactSecrets(scan.last_activity)}</span>
        </p>
      )}
      {error && <ErrorNotice>{error}</ErrorNotice>}

      <div className="button-row">
        <a className={`button ${running ? '' : 'button-primary'}`} href={hrefFor('findings')}>
          {running ? `Findings so far (${findingsCount})` : `Review ${findingsCount} finding${findingsCount === 1 ? '' : 's'}`} <ArrowRight size={16} aria-hidden="true" />
        </a>
        <a className="button button-ghost" href={hrefFor('analytics')}>
          {running ? 'Watch live analysis' : 'See what was done'}
        </a>
      </div>
    </Panel>
  );
}
