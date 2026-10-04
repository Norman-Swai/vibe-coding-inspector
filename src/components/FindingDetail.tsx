import { ArrowLeft, Check, Copy, ExternalLink, Flag, ScrollText, X } from 'lucide-react';
import { useState } from 'react';
import { apiClient } from '../api/client';
import type { Finding, FixReviewDecision, ReviewDecision } from '../contracts/finding';
import { hrefFor } from '../hooks/useHashRoute';
import { formatLocation, formatTime, MODULE_META, redactSecrets } from '../lib/meta';
import { useSettings } from '../lib/settings';
import { ErrorNotice, Field, SeverityBadge, Tag } from './ui';

const REVIEW_LABEL: Record<ReviewDecision, string> = { pending: 'Not reviewed yet', confirmed: 'Confirmed', rejected: 'Rejected', escalated: 'Escalated' };
const REVIEW_TONE = { pending: 'neutral', confirmed: 'success', rejected: 'danger', escalated: 'warning' } as const;
const FIX_LABEL: Record<FixReviewDecision, string> = { pending: 'No decision', approved: 'Approved', declined: 'Declined' };

function cweUrl(cwe?: string | null) {
  const match = /^CWE-(\d+)$/.exec(cwe ?? '');
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : null;
}

/**
 * The Analytics search that lists the activity this finding came from. Header and cookie findings all come from the
 * security module's one "Response headers of <url>" check; other findings are traced by the page or file they are about.
 */
export function traceQueryFor(finding: Finding): string | null {
  const { url, file } = finding.location;
  if (finding.category === 'security' && url && !file) return `Response headers of ${url}`;
  return url ?? file ?? null;
}

export function FindingDetail({
  finding,
  baseUrl,
  onUpdated,
  onBack,
}: {
  finding: Finding;
  baseUrl?: string;
  onUpdated: (finding: Finding) => void;
  onBack?: () => void;
}) {
  const { settings, open } = useSettings();
  const [reason, setReason] = useState('');
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const reviewer = settings.reviewer.trim() || undefined;
  const { evidence, review } = finding;
  const fixReview = finding.fix_review ?? { decision: 'pending' as const };
  const fixDecision = fixReview.decision;
  const cwe = cweUrl(finding.cwe_id);
  const excerpt = redactSecrets(evidence.snippet || '(no excerpt captured)');
  const traceQuery = traceQueryFor(finding);
  const [copied, setCopied] = useState(false);

  async function copyExcerpt() {
    try {
      await navigator.clipboard.writeText(excerpt);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setError('Copy failed: the browser blocked clipboard access.');
    }
  }

  async function run(key: string, action: () => Promise<Finding>) {
    setPending(key);
    setError(null);
    try {
      onUpdated(await action());
      setReason('');
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : 'The update failed.');
    } finally {
      setPending(null);
    }
  }

  // The buttons use aria-disabled (a disabled button drops keyboard focus to <body>), so the handlers enforce the rules.
  const needsReason = (decision: ReviewDecision) => decision === 'rejected' || decision === 'escalated';
  const decide = (decision: ReviewDecision) => {
    if (pending || (needsReason(decision) && !reason.trim())) return;
    void run(decision, () => apiClient.updateReview(finding.id, { decision, reason: reason.trim() || undefined, reviewer, timestamp: new Date().toISOString() }));
  };
  const decideFix = (decision: FixReviewDecision) => {
    if (pending || (decision === 'approved' && review.decision !== 'confirmed')) return;
    void run(`fix-${decision}`, () => apiClient.updateFixReview(finding.id, { decision, reviewer, timestamp: new Date().toISOString() }));
  };

  return (
    <article className="finding-detail" aria-labelledby={`finding-${finding.id}`}>
      {onBack && (
        <button type="button" className="button button-ghost back-button" onClick={onBack}>
          <ArrowLeft size={16} aria-hidden="true" /> All findings
        </button>
      )}
      <header className="detail-header">
        <div className="tag-row">
          <SeverityBadge severity={finding.severity} />
          <Tag tone={finding.verification === 'confirmed' ? 'success' : 'warning'} title={finding.verification === 'confirmed' ? 'Directly observed' : 'Pattern match — a person must confirm it'}>
            {finding.verification === 'confirmed' ? 'Observed' : 'Hypothesis'}
          </Tag>
          {finding.source_modules.map((module) => (
            <Tag key={module}>{MODULE_META[module].label}</Tag>
          ))}
          {cwe && (
            <a className="badge" data-tone="neutral" href={cwe} target="_blank" rel="noreferrer noopener">
              {finding.cwe_id} <ExternalLink size={12} aria-hidden="true" />
            </a>
          )}
        </div>
        {/* Focusable so that opening a finding can move the keyboard here (the list may be hidden behind this detail). */}
        <h3 id={`finding-${finding.id}`} tabIndex={-1}>
          {finding.title}
        </h3>
      </header>

      <section className="detail-section" aria-labelledby={`artifacts-${finding.id}`}>
        <div className="section-title-row">
          <h4 id={`artifacts-${finding.id}`}>Artifacts</h4>
          {traceQuery && (
            <a className="link-button small" href={hrefFor('analytics', { q: traceQuery, source: finding.category })}>
              <ScrollText size={14} aria-hidden="true" /> Trace in Analytics
            </a>
          )}
        </div>
        <dl className="facts">
          <div>
            <dt>Location</dt>
            <dd className="break-anywhere">{formatLocation(finding.location, baseUrl)}</dd>
          </div>
          {finding.location.element && (
            <div>
              <dt>Element</dt>
              <dd className="break-anywhere">{finding.location.element}</dd>
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
              <dd className="break-anywhere">{redactSecrets(evidence.captured_output)}</dd>
            </div>
          )}
          {evidence.occurrences > 1 && (
            <div>
              <dt>Occurrences</dt>
              <dd>{evidence.occurrences}</dd>
            </div>
          )}
        </dl>
        {/* Captured content is untrusted: React renders it as text, never as HTML. */}
        <div className="artifact">
          <div className="artifact-bar">
            <span className="muted small">Captured excerpt</span>
            <button type="button" className="link-button small" onClick={() => void copyExcerpt()}>
              <Copy size={14} aria-hidden="true" /> {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <pre className="evidence" tabIndex={0} aria-label="Evidence excerpt">
            {excerpt}
          </pre>
        </div>
      </section>

      <section className="detail-section">
        <h4>What it means</h4>
        <p>{finding.description_plain}</p>
        <p>
          <strong>Impact:</strong> {finding.impact_plain}
        </p>
      </section>

      <section className="detail-section">
        <h4>Review</h4>
        <p className="review-status">
          <Tag tone={REVIEW_TONE[review.decision]}>{REVIEW_LABEL[review.decision]}</Tag>
          {review.decision !== 'pending' && (
            <span className="muted small">
              {review.reviewer ? `by ${review.reviewer}` : ''} {formatTime(review.timestamp)}
              {review.reason ? ` — “${review.reason}”` : ''}
            </span>
          )}
        </p>
        <Field label="Reason" hint="Required to reject or escalate.">
          {(props) => <textarea {...props} rows={2} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Why is this a false positive, or who should look at it?" />}
        </Field>
        <div className="button-row">
          <button type="button" className="button" data-tone="success" aria-disabled={!!pending} onClick={() => decide('confirmed')}>
            <Check size={16} aria-hidden="true" /> Confirm
          </button>
          <button type="button" className="button" data-tone="danger" aria-disabled={!!pending || !reason.trim()} onClick={() => decide('rejected')}>
            <X size={16} aria-hidden="true" /> Reject
          </button>
          <button type="button" className="button" data-tone="warning" aria-disabled={!!pending || !reason.trim()} onClick={() => decide('escalated')}>
            <Flag size={16} aria-hidden="true" /> Escalate
          </button>
        </div>
        <p className="muted small">
          Reviewing as <strong>{reviewer ?? 'anonymous'}</strong> ·{' '}
          <button type="button" className="link-button" onClick={() => open('review')}>
            {reviewer ? 'Change' : 'Set your name'}
          </button>
        </p>
      </section>

      {finding.fix_suggestion && (
        <section className="detail-section">
          <h4>Suggested fix</h4>
          <p>{finding.fix_suggestion.summary}</p>
          {finding.fix_suggestion.diff && <pre className="evidence">{finding.fix_suggestion.diff}</pre>}
          <p className="review-status">
            <span className="muted small">Fix decision:</span> <Tag tone={fixDecision === 'approved' ? 'success' : fixDecision === 'declined' ? 'danger' : 'neutral'}>{FIX_LABEL[fixDecision]}</Tag>
            {fixDecision !== 'pending' && (
              <span className="muted small">
                {fixReview.reviewer ? `by ${fixReview.reviewer}` : ''} {formatTime(fixReview.timestamp)}
              </span>
            )}
          </p>
          <div className="button-row">
            <button type="button" className="button" aria-disabled={!!pending || review.decision !== 'confirmed'} onClick={() => decideFix('approved')}>
              Approve fix
            </button>
            <button type="button" className="button button-ghost" aria-disabled={!!pending} onClick={() => decideFix('declined')}>
              Decline fix
            </button>
          </div>
          <p className="muted small">{review.decision === 'confirmed' ? 'Approving records your decision; nothing is changed in the code automatically.' : 'Confirm the finding before approving a fix.'}</p>
        </section>
      )}
      {error && <ErrorNotice>{error}</ErrorNotice>}
    </article>
  );
}
