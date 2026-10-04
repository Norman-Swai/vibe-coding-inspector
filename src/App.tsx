import { BarChart3, Home, ListChecks, Rocket, ScanSearch, Settings as SettingsIcon } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from './api/client';
import { EMPTY_FINDINGS_UI, type FindingsUiState } from './components/FindingsPanel';
import { EMPTY_DRAFT, type LaunchDraft } from './components/LaunchPanel';
import { finishedModules } from './components/ScanMonitor';
import { SettingsDrawer } from './components/SettingsDrawer';
import type { ScanRequest } from './contracts/finding';
import { hrefFor, useHashRoute, type View } from './hooks/useHashRoute';
import { useScan } from './hooks/useScan';
import { MODULES, redactSecrets } from './lib/meta';
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
  const [findingsUi, setFindingsUi] = useState<FindingsUiState>(EMPTY_FINDINGS_UI);
  const updateFindingsUi = useCallback((patch: Partial<FindingsUiState>) => setFindingsUi((current) => ({ ...current, ...patch })), []);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  // Explains why a remembered scan disappeared; lives here because useScan resets its own state when the id changes.
  const [notice, setNotice] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const forgetScan = useCallback((message: string) => {
    writeLastScan(null);
    setScanId(null);
    setNotice(message);
  }, []);
  const { scan, findings, activity, activityDropped, error: pollError, replaceFinding } = useScan(scanId, forgetScan);
  const error = pollError ?? notice;
  const running = scan?.status === 'running';
  // From the same snapshot as the status, so live text and badges never show a stale count.
  const findingsCount = scan?.summary.total_findings ?? 0;

  async function startScan(request: ScanRequest) {
    setStarting(true);
    setStartError(null);
    try {
      const { scan_id: id } = await apiClient.startScan(request);
      writeLastScan(id);
      setLocalStart(Date.now());
      setNotice(null);
      setFindingsUi(EMPTY_FINDINGS_UI);
      setScanId(id);
      setAnnouncement(`Scan started for ${request.target_url}.`);
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

  // Move focus to the new view's heading when the view changes (never on first load) so keyboard and
  // screen-reader users land in the right place. Comparing views keeps this correct under StrictMode's double effects.
  const shownView = useRef(view);
  useEffect(() => {
    if (shownView.current === view) return;
    shownView.current = view;
    window.scrollTo({ top: 0 });
    document.querySelector<HTMLElement>('[data-view-heading]')?.focus({ preventScroll: true });
  }, [view]);

  // Announce the end of a scan on whichever view is open (the start is announced when it is requested).
  const lastStatus = useRef<{ id: string | null; status: string | null }>({ id: null, status: null });
  useEffect(() => {
    if (!scan) return;
    const previous = lastStatus.current;
    lastStatus.current = { id: scan.id, status: scan.status };
    if (previous.id === scan.id && previous.status === 'running' && scan.status === 'completed') {
      const failed = MODULES.filter((module) => scan.modules[module].state === 'failed').length;
      const total = scan.summary.total_findings;
      setAnnouncement(`Scan complete: ${total} finding${total === 1 ? '' : 's'}${failed ? `, ${failed} module${failed === 1 ? '' : 's'} failed` : ''}.`);
    }
  }, [scan]);

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
                  {target === 'findings' && scan && <span className="nav-count">{findingsCount}</span>}
                </a>
              ))}
            </nav>
            {running && scan && (
              <a className="scan-chip" href={hrefFor('launch')} title={scan.last_activity ? redactSecrets(scan.last_activity) : undefined}>
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
          {view === 'overview' && <OverviewView scan={scan} findingsCount={findingsCount} />}
          {view === 'launch' && (
            <LaunchView
              draft={draft}
              onDraftChange={updateDraft}
              scan={scan}
              error={error}
              findingsCount={findingsCount}
              starting={starting}
              startError={startError}
              localStart={localStart}
              onStart={(request) => void startScan(request)}
            />
          )}
          {view === 'analytics' && <AnalyticsView scan={scan} activity={activity} activityDropped={activityDropped} error={error} query={params.get('q') ?? ''} />}
          {view === 'findings' && (
            <FindingsView scan={scan} findings={findings} error={error} ui={findingsUi} onUiChange={updateFindingsUi} onFindingUpdated={replaceFinding} />
          )}
        </main>
        {/* One polite live region for the whole app: scan started / finished, whichever view is open. */}
        <p className="visually-hidden" role="status" aria-live="polite">
          {announcement}
        </p>
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
