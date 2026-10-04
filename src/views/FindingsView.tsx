import { ListChecks } from 'lucide-react';
import { FindingsPanel, type FindingsUiState } from '../components/FindingsPanel';
import { ReportPanel } from '../components/ReportPanel';
import { EmptyState, ErrorNotice, Panel } from '../components/ui';
import { ViewHeader } from '../components/ViewHeader';
import type { Finding, ScanStatusResponse } from '../contracts/finding';
import { hrefFor } from '../hooks/useHashRoute';
import { MODULE_META, MODULES } from '../lib/meta';

/** Headline numbers that the severity filters below do not show: how the findings were established and reviewed. */
function FindingsSummary({ scan, findings }: { scan: ScanStatusResponse; findings: Finding[] }) {
  const observed = findings.filter((finding) => finding.verification === 'confirmed').length;
  const decided = findings.filter((finding) => finding.review.decision !== 'pending');
  const byDecision = (decision: string) => decided.filter((finding) => finding.review.decision === decision).length;
  const notRun = MODULES.filter((module) => ['failed', 'skipped'].includes(scan.modules[module].state));
  const running = scan.status === 'running';

  return (
    <Panel title="Summary" className="summary-panel">
      <ul className="metric-grid" role="list">
        <li className="metric">
          <span className="metric-value">{findings.length}</span>
          <span className="metric-label">Observations{running ? ' so far' : ''}</span>
          <span className="muted small">
            {observed} observed directly · {findings.length - observed} hypotheses to confirm
          </span>
        </li>
        <li className="metric">
          <span className="metric-value">
            {decided.length}/{findings.length}
          </span>
          <span className="metric-label">Reviewed</span>
          <span className="muted small">
            {byDecision('confirmed')} confirmed · {byDecision('rejected')} rejected · {byDecision('escalated')} escalated
          </span>
        </li>
        {MODULES.map((module) => {
          const count = findings.filter((finding) => finding.source_modules.includes(module)).length;
          const state = scan.modules[module].state;
          return (
            <li key={module} className="metric" data-state={state}>
              <span className="metric-value">{state === 'failed' || state === 'skipped' ? '—' : count}</span>
              <span className="metric-label">{MODULE_META[module].label}</span>
              <span className="muted small">{state === 'failed' ? 'module failed' : state === 'skipped' ? 'not run' : state === 'done' ? 'finished' : 'in progress'}</span>
            </li>
          );
        })}
      </ul>
      {notRun.length > 0 && (
        <p className="notice" data-tone="warning">
          {notRun.map((module) => MODULE_META[module].label).join(' and ')} {notRun.length === 1 ? 'was' : 'were'} skipped or failed, so{' '}
          {notRun.length === 1 ? 'its' : 'their'} checks are not reflected here. <a href={hrefFor('analytics')}>See why in Analytics</a>.
        </p>
      )}
    </Panel>
  );
}

export function FindingsView({
  scan,
  findings,
  error,
  ui,
  onUiChange,
  onFindingUpdated,
}: {
  scan: ScanStatusResponse | null;
  findings: Finding[];
  error: string | null;
  ui: FindingsUiState;
  onUiChange: (patch: Partial<FindingsUiState>) => void;
  onFindingUpdated: (finding: Finding) => void;
}) {
  return (
    <>
      <ViewHeader
        title="Findings"
        description={
          scan ? (
            <>
              Observations from the scan of <span className="break-anywhere">{scan.target_url}</span>, each with the artifacts it is based on.
            </>
          ) : (
            'Observations from the latest scan, each with the artifacts it is based on.'
          )
        }
      />
      {error && <ErrorNotice>{error}</ErrorNotice>}
      {!scan ? (
        <EmptyState icon={ListChecks} title="No findings yet">
          <a href={hrefFor('launch')}>Launch a scan</a>; findings appear here as each module reports.
        </EmptyState>
      ) : (
        <>
          <FindingsSummary scan={scan} findings={findings} />
          <FindingsPanel scan={scan} findings={findings} ui={ui} onUiChange={onUiChange} onFindingUpdated={onFindingUpdated} />
          <ReportPanel scan={scan} findingsVersion={findings} />
        </>
      )}
    </>
  );
}
