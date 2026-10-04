import { Eye, EyeOff, FileDown, FileJson, Printer } from 'lucide-react';
import { useEffect, useState } from 'react';
import { apiClient, type ReportFormat } from '../api/client';
import type { ScanStatusResponse } from '../contracts/finding';
import { ErrorNotice, Panel } from './ui';

function download(content: string, format: ReportFormat, scan: ScanStatusResponse) {
  let host = 'scan';
  try {
    host = new URL(scan.target_url).host.replace(/[^a-z0-9.-]+/gi, '-');
  } catch {
    // Keep the default name.
  }
  const stamp = new Date(scan.created_at).toISOString().slice(0, 16).replace(/[:T]/g, '-');
  const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `inspection-${host}-${stamp}.${format === 'json' ? 'json' : 'md'}`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function ReportPanel({ scan, findingsVersion }: { scan: ScanStatusResponse | null; findingsVersion: unknown }) {
  const [preview, setPreview] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [busy, setBusy] = useState<ReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [printRequested, setPrintRequested] = useState(false);

  // Any change to the scan or a review decision makes a loaded preview stale.
  useEffect(() => setPreview(null), [scan?.id, scan?.status, findingsVersion]);
  useEffect(() => {
    if (!showPreview || preview !== null || !scan) return;
    let cancelled = false;
    apiClient
      .getReport(scan.id, 'markdown')
      .then((text) => !cancelled && setPreview(text))
      .catch((reportError: Error) => {
        if (cancelled) return;
        setError(reportError.message);
        setShowPreview(false);
      });
    return () => {
      cancelled = true;
    };
  }, [showPreview, preview, scan]);

  // Printing uses the full Markdown report (print styles hide everything else), so load it first.
  useEffect(() => {
    if (!printRequested || preview === null) return;
    setPrintRequested(false);
    requestAnimationFrame(() => window.print());
  }, [printRequested, preview]);

  async function save(format: ReportFormat) {
    if (!scan) return;
    setBusy(format);
    setError(null);
    try {
      download(await apiClient.getReport(scan.id, format), format, scan);
    } catch (reportError) {
      setError(reportError instanceof Error ? reportError.message : 'Export failed.');
    } finally {
      setBusy(null);
    }
  }

  return (
    <Panel
      id="report"
      title="Report"
      description={
        !scan
          ? 'Export findings, coverage and review decisions once a scan has run.'
          : scan.status === 'running'
            ? 'The scan is still running; an export now will be partial.'
            : 'Includes coverage per module, every finding with its evidence, and each review decision (undecided ones are marked pending).'
      }
      className="report-panel"
    >
      <div className="button-row">
        <button type="button" className="button" disabled={!scan || busy !== null} onClick={() => void save('markdown')}>
          <FileDown size={16} aria-hidden="true" /> {busy === 'markdown' ? 'Preparing…' : 'Download Markdown'}
        </button>
        <button type="button" className="button" disabled={!scan || busy !== null} onClick={() => void save('json')}>
          <FileJson size={16} aria-hidden="true" /> {busy === 'json' ? 'Preparing…' : 'Download JSON'}
        </button>
        <button type="button" className="button button-ghost" disabled={!scan} aria-expanded={showPreview} onClick={() => setShowPreview((value) => !value)}>
          {showPreview ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />} {showPreview ? 'Hide preview' : 'Preview'}
        </button>
        <button
          type="button"
          className="button button-ghost"
          disabled={!scan}
          onClick={() => {
            setShowPreview(true);
            setPrintRequested(true);
          }}
        >
          <Printer size={16} aria-hidden="true" /> Print / PDF
        </button>
      </div>
      {error && <ErrorNotice>{error}</ErrorNotice>}
      {showPreview && scan && (
        <pre className="evidence report-preview" tabIndex={0} aria-label="Markdown report preview" aria-busy={preview === null}>
          {preview ?? 'Loading…'}
        </pre>
      )}
    </Panel>
  );
}
