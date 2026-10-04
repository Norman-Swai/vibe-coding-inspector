import type { ScanStatusResponse } from '../contracts/finding';
import { formatDuration, MODULE_META, MODULES } from '../lib/meta';
import { Panel, StateBadge } from './ui';

/** What each module covered, skipped or failed on, with its coverage notes. */
export function CoveragePanel({ scan }: { scan: ScanStatusResponse }) {
  return (
    <Panel title="Coverage by module" description="What each module looked at, and anything it skipped or could not do." className="coverage-panel">
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
                <details className="module-notes" open={report.state === 'skipped' || undefined}>
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
