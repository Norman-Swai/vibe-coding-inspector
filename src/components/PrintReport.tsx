import { useId } from 'react';
import type { ActivityEvent, Finding, FixReviewDecision, InspectionMode, ReviewDecision, ScanStatusResponse } from '../contracts/finding';
import { compareSeverity, formatDuration, formatLocation, formatTime, MODULE_META, MODULE_STATE_LABEL, MODULES, redactSecrets, SEVERITIES, SEVERITY_META } from '../lib/meta';
import { isCommand, sourceLabel } from './ActivityLog';

const MODE_LABEL: Record<InspectionMode, string> = { localhost: 'Authorised localhost', 'public-readonly': 'Public read-only' };
const REVIEW_LABEL: Record<ReviewDecision, string> = { pending: 'Pending', confirmed: 'Confirmed', rejected: 'Rejected', escalated: 'Escalated' };
const FIX_LABEL: Record<FixReviewDecision, string> = { pending: 'Pending', approved: 'Approved', declined: 'Declined' };

/** "Confirmed by Norman, 4 Oct 2026, 05:00 — “reason”". */
function decisionText(label: string, reviewer?: string | null, timestamp?: string | null, reason?: string | null) {
  const when = formatTime(timestamp);
  return `${label}${reviewer ? ` by ${reviewer}` : ''}${when ? `, ${when}` : ''}${reason ? ` — “${reason}”` : ''}`;
}

/**
 * The report that Print / PDF prints, built from the scan, activity and findings already in the client: the same
 * sections as the Markdown export. It carries the hidden attribute on screen; the print stylesheet shows it and hides all else.
 */
export function PrintReport({
  scan,
  findings,
  activity,
  activityDropped,
}: {
  scan: ScanStatusResponse;
  findings: Finding[];
  activity: ActivityEvent[];
  activityDropped: number;
}) {
  const titleId = useId();
  const sorted = [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
  const bySeverity = SEVERITIES.map((severity) => `${SEVERITY_META[severity].label} ${findings.filter((finding) => finding.severity === severity).length}`).join(', ');
  const requests = activity.filter((event) => event.request).length;
  const checks = activity.filter((event) => event.kind === 'check');
  const commands = activity.filter(isCommand);

  return (
    <section className="print-report" aria-labelledby={titleId} hidden>
      <h1 id={titleId}>Inspection report — {scan.target_url}</h1>
      <dl className="print-facts">
        <div>
          <dt>Scan ID</dt>
          <dd>{scan.id}</dd>
        </div>
        <div>
          <dt>Mode</dt>
          <dd>{MODE_LABEL[scan.inspection_mode]}</dd>
        </div>
        <div>
          <dt>Repository</dt>
          <dd>{scan.repo_path || 'not provided'}</dd>
        </div>
        <div>
          <dt>Started</dt>
          <dd>{formatTime(scan.created_at)}</dd>
        </div>
        <div>
          <dt>Finished</dt>
          <dd>{scan.finished_at ? formatTime(scan.finished_at) : 'still running (partial report)'}</dd>
        </div>
        <div>
          <dt>Limits</dt>
          <dd>
            {scan.options.max_pages} pages, {scan.options.timeout_seconds} s request timeout
          </dd>
        </div>
        <div>
          <dt>Findings</dt>
          <dd>
            {findings.length} ({bySeverity})
          </dd>
        </div>
      </dl>

      <h2>Coverage</h2>
      <table className="print-table">
        <thead>
          <tr>
            <th scope="col">Module</th>
            <th scope="col">State</th>
            <th scope="col">Scanned</th>
            <th scope="col">Duration</th>
            <th scope="col">Notes</th>
          </tr>
        </thead>
        <tbody>
          {MODULES.map((module) => {
            const report = scan.modules[module];
            return (
              <tr key={module}>
                <th scope="row">{MODULE_META[module].label}</th>
                <td>{MODULE_STATE_LABEL[report.state]}</td>
                <td>{report.state === 'done' ? report.scanned_label || String(report.scanned) : '—'}</td>
                <td>{report.duration_ms != null ? formatDuration(report.duration_ms) : '—'}</td>
                <td>
                  {report.error && <p className="print-error">Error: {report.error}</p>}
                  {report.notes.length > 0 ? (
                    <ul>
                      {report.notes.map((note) => (
                        <li key={note}>{note}</li>
                      ))}
                    </ul>
                  ) : (
                    !report.error && '—'
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <h2>What was done</h2>
      <dl className="print-facts">
        <div>
          <dt>HTTP requests sent</dt>
          <dd>{requests}</dd>
        </div>
        <div>
          <dt>Checks evaluated</dt>
          <dd>{checks.length}</dd>
        </div>
        <div>
          <dt>Commands run</dt>
          <dd>{commands.length}</dd>
        </div>
        {activityDropped > 0 && (
          <div>
            <dt>Not recorded</dt>
            <dd>{activityDropped} activity events (cap reached)</dd>
          </div>
        )}
      </dl>
      {commands.map((event) => (
        <div key={event.seq} className="print-command">
          <p>
            <strong>{redactSecrets(event.message)}</strong>
          </p>
          <pre className="print-excerpt">{redactSecrets(event.output || '(no output)')}</pre>
        </div>
      ))}
      {checks.length > 0 && (
        <table className="print-table">
          <thead>
            <tr>
              <th scope="col">Module</th>
              <th scope="col">Check</th>
            </tr>
          </thead>
          <tbody>
            {checks.map((event) => (
              <tr key={event.seq}>
                <td>{sourceLabel(event.module)}</td>
                <td>{redactSecrets(event.message)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Findings</h2>
      {sorted.length === 0 && <p>No findings were reported by the modules that completed.</p>}
      {sorted.map((finding, index) => {
        const { evidence, review } = finding;
        const fix = finding.fix_review;
        return (
          <article key={finding.id} className="print-finding">
            <h3>
              {index + 1}. {finding.title}
            </h3>
            <dl className="print-facts">
              <div>
                <dt>Severity</dt>
                <dd>{SEVERITY_META[finding.severity].label}</dd>
              </div>
              <div>
                <dt>Verification</dt>
                <dd>{finding.verification === 'confirmed' ? 'Observed directly' : 'Hypothesis — a person must confirm it'}</dd>
              </div>
              <div>
                <dt>Module</dt>
                <dd>{finding.source_modules.map((module) => MODULE_META[module].label).join(', ')}</dd>
              </div>
              <div>
                <dt>Category</dt>
                <dd>{MODULE_META[finding.category].label}</dd>
              </div>
              <div>
                <dt>Location</dt>
                <dd>{formatLocation(finding.location, scan.target_url)}</dd>
              </div>
              {finding.location.element && (
                <div>
                  <dt>Element</dt>
                  <dd>{finding.location.element}</dd>
                </div>
              )}
              {evidence.check && (
                <div>
                  <dt>Check</dt>
                  <dd>{evidence.check}</dd>
                </div>
              )}
              {evidence.captured_output && (
                <div>
                  <dt>Source</dt>
                  <dd>{redactSecrets(evidence.captured_output)}</dd>
                </div>
              )}
              {evidence.occurrences > 1 && (
                <div>
                  <dt>Occurrences</dt>
                  <dd>{evidence.occurrences}</dd>
                </div>
              )}
              {finding.cwe_id && (
                <div>
                  <dt>CWE</dt>
                  <dd>{finding.cwe_id}</dd>
                </div>
              )}
              <div>
                <dt>Review</dt>
                <dd>{decisionText(REVIEW_LABEL[review.decision], review.reviewer, review.timestamp, review.reason)}</dd>
              </div>
              <div>
                <dt>Fix decision</dt>
                <dd>{fix ? decisionText(FIX_LABEL[fix.decision], fix.reviewer, fix.timestamp) : FIX_LABEL.pending}</dd>
              </div>
            </dl>
            {/* Captured content is untrusted: React renders it as text, never as HTML. */}
            <pre className="print-excerpt">{redactSecrets(evidence.snippet || '(no excerpt captured)')}</pre>
            <p>{finding.description_plain}</p>
            <p>
              <strong>Impact:</strong> {finding.impact_plain}
            </p>
            {finding.fix_suggestion && (
              <>
                <p>
                  <strong>Suggested fix:</strong> {finding.fix_suggestion.summary}
                </p>
                {finding.fix_suggestion.diff && <pre className="print-excerpt">{finding.fix_suggestion.diff}</pre>}
              </>
            )}
          </article>
        );
      })}
    </section>
  );
}
