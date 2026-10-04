import { ScanSearch, Settings as SettingsIcon } from 'lucide-react';
import { useState } from 'react';
import { apiClient } from './api/client';
import { CoveragePanel } from './components/CoveragePanel';
import { FindingsPanel } from './components/FindingsPanel';
import { LaunchPanel } from './components/LaunchPanel';
import { ReportPanel } from './components/ReportPanel';
import { SettingsDrawer } from './components/SettingsDrawer';
import type { ScanRequest } from './contracts/finding';
import { useScan } from './hooks/useScan';
import { SettingsProvider, useSettings } from './lib/settings';

function Workspace() {
  const { isOpen, open } = useSettings();
  const [scanId, setScanId] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const { scan, findings, error, replaceFinding } = useScan(scanId);

  async function startScan(request: ScanRequest) {
    setStarting(true);
    setStartError(null);
    try {
      setScanId((await apiClient.startScan(request)).scan_id);
    } catch (scanError) {
      setStartError(scanError instanceof Error ? scanError.message : 'Unable to start the scan.');
    } finally {
      setStarting(false);
    }
  }

  return (
    <>
      <div className="app" inert={isOpen}>
        <a className="skip-link" href="#main">
          Skip to content
        </a>
        <header className="topbar">
          <div className="topbar-inner">
            <a className="brand" href="#main">
              <span className="brand-mark" aria-hidden="true">
                <ScanSearch size={18} />
              </span>
              <span className="brand-name">Vibe Coding Inspector</span>
            </a>
            <nav className="topnav" aria-label="Sections">
              <a href="#scan">Scan</a>
              <a href="#findings">Findings</a>
              <a href="#report">Report</a>
            </nav>
            <button type="button" className="icon-button" onClick={() => open()} aria-haspopup="dialog" aria-label="Settings">
              <SettingsIcon size={20} aria-hidden="true" />
              <span className="icon-button-label">Settings</span>
            </button>
          </div>
        </header>

        <main id="main" className="page" tabIndex={-1}>
          <div className="page-intro">
            <h1>Inspect a web app</h1>
            <p className="muted">Runtime, code, security and compliance checks. Every finding shows the evidence it is based on.</p>
          </div>
          <div className="top-grid">
            <LaunchPanel busy={starting} error={startError} onStart={(request) => void startScan(request)} />
            <CoveragePanel scan={scan} error={error} />
          </div>
          <FindingsPanel key={scanId ?? 'none'} scan={scan} findings={findings} onFindingUpdated={replaceFinding} />
          <ReportPanel scan={scan} findingsVersion={findings} />
        </main>
      </div>
      <SettingsDrawer />
    </>
  );
}

export default function App() {
  return (
    <SettingsProvider>
      <Workspace />
    </SettingsProvider>
  );
}
