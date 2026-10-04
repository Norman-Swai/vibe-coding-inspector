import { Radar } from 'lucide-react';
import type { ScanStatusResponse } from '../contracts/finding';
import { formatDuration, formatTime, MODULE_META, MODULES } from '../lib/meta';
import { EmptyState, ErrorNotice, Panel, StateBadge, Tag } from './ui';

export function CoveragePanel({ scan, error }: { scan: ScanStatusResponse | null; error: string | null }) {
  if (!scan) {
    return (
      <Panel title="Coverage" description="What each module checked in the current scan.">
        {error ? <ErrorNotice>{error}</ErrorNotice> : <EmptyState icon={Radar} title="No scan yet">Start a scan to see each module's progress and what it covered.</EmptyState>}
      </Panel>
    );
  }

  const finished = MODULES.filter((module) => ['done', 'failed', 'skipped'].includes(scan.modules[module].state)).length;
  const running = scan.status === 'running';
  const totalMs = scan.finished_at ? new Date(scan.finished_at).getTime() - new Date(scan.created_at).getTime() : null;

  return (
    <Panel
      title="Coverage"
      description={
        <>
          <span className="break-anywhere">{scan.target_url}</span> · {scan.inspection_mode === 'localhost' ? 'Localhost' : 'Public site'} · started {formatTime(scan.created_at)}
        </>
      }
      actions={running ? <Tag tone="warning">Running {finished}/{MODULES.length}</Tag> : <Tag tone="success">Completed in {formatDuration(totalMs)}</Tag>}
    >
      <div className="progress" role="progressbar" aria-label="Modules finished" aria-valuemin={0} aria-valuemax={MODULES.length} aria-valuenow={finished}>
        <span style={{ width: `${(finished / MODULES.length) * 100}%` }} />
      </div>
      {error && <ErrorNotice>{error}</ErrorNotice>}
      <ul className="module-list" role="list">
        {MODULES.map((module) => {
          const report = scan.modules[module];
          const { icon: Icon, label, summary } = MODULE_META[module];
          return (
            <li key={module} className="module-row" data-state={report.state}>
              <div className="module-head">
                <span className="module-icon">
                  <Icon size={18} aria-hidden="true" />
                </span>
                <div className="module-title">
                  <strong>{label}</strong>
                  <span className="muted small">{report.state === 'done' ? report.scanned_label : summary}</span>
                </div>
                <div className="module-meta">
                  {report.duration_ms != null && <span className="muted small">{formatDuration(report.duration_ms)}</span>}
                  <StateBadge state={report.state} />
                </div>
              </div>
              {report.error && <p className="module-error">{report.error}</p>}
              {report.notes.length > 0 && (
                <details className="module-notes">
                  <summary>
                    {report.state === 'skipped' ? 'Why skipped' : 'Coverage notes'} ({report.notes.length})
                  </summary>
                  <ul>
                    {report.notes.map((note) => (
                      <li key={note}>{note}</li>
                    ))}
                  </ul>
                </details>
              )}
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}
