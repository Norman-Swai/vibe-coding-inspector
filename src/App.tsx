import { BarChart3, Home, ListChecks, Rocket, ScanSearch, Settings as SettingsIcon } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from './api/client';
import { EMPTY_DRAFT, type LaunchDraft } from './components/LaunchPanel';
import { finishedModules } from './components/ScanMonitor';
import { SettingsDrawer } from './components/SettingsDrawer';
import type { ScanRequest } from './contracts/finding';
import { hrefFor, useHashRoute, type View } from './hooks/useHashRoute';
import { useScan } from './hooks/useScan';
import { MODULES } from './lib/meta';
import { SettingsProvider, useSettings } from './lib/settings';
import { AnalyticsView } from './views/AnalyticsView';
import { FindingsView } from './views/FindingsView';
import { LaunchView } from './views/LaunchView';
import { OverviewView } from './views/OverviewView';

const NAV: { view: View; label: string; icon: typeof Home }[] = [
  { view: 'overview', label: 'Overview', icon: Home },
  { view: 'launch', label: 'Launch', icon: Rocket },
  { view: 'analytics', label: 'Analytics', icon: BarChart3 },
  { view: 'findings', label: 'Findings', icon: ListChecks },
];

export const LAST_SCAN_KEY = 'vci-last-scan';

function readLastScan(): string | null {
  try {
    return window.localStorage.getItem(LAST_SCAN_KEY);
  } catch {
    return null;
  }
}

function writeLastScan(scanId: string | null) {
  try {
    if (scanId) window.localStorage.setItem(LAST_SCAN_KEY, scanId);
    else window.localStorage.removeItem(LAST_SCAN_KEY);
  } catch {
    // Without storage the current scan is simply forgotten on reload.
  }
}

function Workspace() {
  const { isOpen, open } = useSettings();
  const { view, params } = useHashRoute();
  // The current scan survives reloads and view changes; it is forgotten if the backend no longer has it.
  const [scanId, setScanId] = useState<string | null>(readLastScan);
  const [localStart, setLocalStart] = useState<number | null>(null);
  const [draft, setDraft] = useState<LaunchDraft>(EMPTY_DRAFT);
  const updateDraft = useCallback((patch: Partial<LaunchDraft>) => setDraft((current) => ({ ...current, ...patch })), []);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const forgetScan = useCallback(() => {
    writeLastScan(null);
    setScanId(null);
  }, []);
  const { scan, findings, activity, activityDropped, error, replaceFinding } = useScan(scanId, forgetScan);
  const running = scan?.status === 'running';

  async function startScan(request: ScanRequest) {
    setStarting(true);
    setStartError(null);
    try {
      const { scan_id: id } = await apiClient.startScan(request);
      writeLastScan(id);
      setLocalStart(Date.now());
      setScanId(id);
      // On stacked (phone) layouts the live monitor sits below the form: bring it into view.
      requestAnimationFrame(() => {
        const monitor = document.querySelector<HTMLElement>('.monitor-panel');
        if (monitor && monitor.getBoundingClientRect().top > window.innerHeight * 0.6) monitor.scrollIntoView({ block: 'start' });
      });
    } catch (scanError) {
      setStartError(scanError instanceof Error ? scanError.message : 'Unable to start the scan.');
    } finally {
      setStarting(false);
    }
  }

  // Move focus to the new view's heading (not on first load) so keyboard and screen-reader users land in the right place.
  const firstRender = useRef(true);
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    window.scrollTo({ top: 0 });
    document.querySelector<HTMLElement>('[data-view-heading]')?.focus({ preventScroll: true });
  }, [view]);

  useEffect(() => {
    const label = NAV.find((item) => item.view === view)?.label ?? '';
    document.title = `${running ? 'Scanning… · ' : ''}${label} · Vibe Coding Inspector`;
  }, [view, running]);

  return (
    <>
      <div className="app" inert={isOpen}>
        {/* Not href="#main": the hash is the router, so this moves focus without navigating. */}
        <button type="button" className="skip-link" onClick={() => document.getElementById('main')?.focus()}>
          Skip to content
        </button>
        <header className="topbar">
          <div className="topbar-inner">
            <a className="brand" href={hrefFor('overview')}>
              <span className="brand-mark" aria-hidden="true">
                <ScanSearch size={18} />
              </span>
              <span className="brand-name">Vibe Coding Inspector</span>
            </a>
            <nav className="viewnav" aria-label="Views">
              {NAV.map(({ view: target, label, icon: Icon }) => (
                <a key={target} href={hrefFor(target)} aria-current={view === target ? 'page' : undefined}>
                  <span className="viewnav-icon">
                    {target === 'launch' && running ? <span className="spinner" aria-hidden="true" /> : <Icon size={18} aria-hidden="true" />}
                  </span>
                  <span className="viewnav-label">{label}</span>
                  {target === 'findings' && scan && <span className="nav-count">{findings.length}</span>}
                </a>
              ))}
            </nav>
            {running && scan && (
              <a className="scan-chip" href={hrefFor('launch')} title={scan.last_activity ?? undefined}>
                <span className="spinner" aria-hidden="true" />
                <span className="scan-chip-label">Scanning</span> {finishedModules(scan)}/{MODULES.length}
                <span className="visually-hidden"> modules finished</span>
              </a>
            )}
            <button type="button" className="icon-button" onClick={() => open()} aria-haspopup="dialog" aria-label="Settings">
              <SettingsIcon size={20} aria-hidden="true" />
              <span className="icon-button-label">Settings</span>
            </button>
          </div>
        </header>

        <main id="main" className="page" data-view={view} tabIndex={-1}>
          {view === 'overview' && <OverviewView scan={scan} findingsCount={findings.length} />}
          {view === 'launch' && (
            <LaunchView
              draft={draft}
              onDraftChange={updateDraft}
              scan={scan}
              error={error}
              findingsCount={findings.length}
              starting={starting}
              startError={startError}
              localStart={localStart}
              onStart={(request) => void startScan(request)}
            />
          )}
          {view === 'analytics' && <AnalyticsView scan={scan} activity={activity} activityDropped={activityDropped} error={error} query={params.get('q') ?? ''} />}
          {view === 'findings' && <FindingsView scan={scan} findings={findings} error={error} scanId={scanId} onFindingUpdated={replaceFinding} />}
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
