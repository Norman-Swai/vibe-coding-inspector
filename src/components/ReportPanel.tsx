import { Eye, EyeOff, FileDown, FileJson, Printer } from 'lucide-react';
import { useEffect, useState } from 'react';
import { apiClient, type ReportFormat } from '../api/client';
import type { Finding, ScanStatusResponse } from '../contracts/finding';
import { downloadText } from '../lib/download';
import { PrintReport } from './PrintReport';
import { ErrorNotice, Panel } from './ui';

export function ReportPanel({ scan, findings }: { scan: ScanStatusResponse | null; findings: Finding[] }) {
  const [preview, setPreview] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [busy, setBusy] = useState<ReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Any change to the scan or a review decision makes a loaded preview stale.
  useEffect(() => setPreview(null), [scan?.id, scan?.status, findings]);
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

  async function save(format: ReportFormat) {
    if (!scan) return;
    setBusy(format);
    setError(null);
    try {
      const report = await apiClient.getReport(scan.id, format);
      downloadText(report, format === 'json' ? 'application/json' : 'text/markdown', scan, 'inspection', format === 'json' ? 'json' : 'md');
    } catch (reportError) {
      setError(reportError instanceof Error ? reportError.message : 'Export failed.');
    } finally {
      setBusy(null);
    }
  }

  return (
    <Panel
      title="Export report"
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
        {/* Prints the formatted report below, built from the data already here (print styles hide everything else). */}
        <button type="button" className="button button-ghost" disabled={!scan} onClick={() => window.print()}>
          <Printer size={16} aria-hidden="true" /> Print / PDF
        </button>
      </div>
      {error && <ErrorNotice>{error}</ErrorNotice>}
      {showPreview && scan && (
        <pre className="evidence report-preview" tabIndex={0} aria-label="Markdown report preview" aria-busy={preview === null}>
          {preview ?? 'Loading…'}
        </pre>
      )}
      {scan && <PrintReport scan={scan} findings={findings} />}
    </Panel>
  );
}
