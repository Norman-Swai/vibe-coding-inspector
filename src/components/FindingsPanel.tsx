import { CheckCircle2, FilterX, Hourglass, ListChecks, Search } from 'lucide-react';
import { type ReactNode, useEffect, useMemo, useRef } from 'react';
import type { Finding, ModuleName, ScanStatusResponse, Severity } from '../contracts/finding';
import { useMediaQuery } from '../hooks/useMediaQuery';
import { compareSeverity, formatLocation, MODULE_META, MODULES, SEVERITIES, SEVERITY_META } from '../lib/meta';
import { FindingDetail } from './FindingDetail';
import { EmptyState, Panel, SeverityBadge } from './ui';

const NARROW = '(max-width: 899px)';

function matchesQuery(finding: Finding, query: string) {
  if (!query) return true;
  const haystack = `${finding.title} ${finding.location.file ?? ''} ${finding.location.url ?? ''} ${finding.cwe_id ?? ''}`.toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .every((word) => haystack.includes(word));
}

/** Selection and filters. Owned by the app shell so they survive a round trip to Analytics ("Trace" then Back). */
export interface FindingsUiState {
  severities: Severity[];
  module: ModuleName | 'all';
  query: string;
  selectedId: string | null;
  detailOpen: boolean;
}

export const EMPTY_FINDINGS_UI: FindingsUiState = { severities: [], module: 'all', query: '', selectedId: null, detailOpen: false };

export function FindingsPanel({
  scan,
  findings,
  ui,
  onUiChange,
  onFindingUpdated,
}: {
  scan: ScanStatusResponse | null;
  findings: Finding[];
  ui: FindingsUiState;
  onUiChange: (patch: Partial<FindingsUiState>) => void;
  onFindingUpdated: (finding: Finding) => void;
}) {
  const narrow = useMediaQuery(NARROW);
  const { module, query, selectedId, detailOpen } = ui;
  const severities = useMemo(() => new Set(ui.severities), [ui.severities]);
  const setModule = (value: ModuleName | 'all') => onUiChange({ module: value });
  const setQuery = (value: string) => onUiChange({ query: value });
  const setSeverities = (value: Set<Severity>) => onUiChange({ severities: [...value] });
  const detailRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const sorted = useMemo(() => [...findings].sort((a, b) => compareSeverity(a.severity, b.severity) || a.title.localeCompare(b.title)), [findings]);
  // Severity counts respect the other filters, so the chips always describe what clicking them would show.
  const facetBase = useMemo(() => sorted.filter((f) => (module === 'all' || f.source_modules.includes(module)) && matchesQuery(f, query.trim())), [sorted, module, query]);
  const visible = useMemo(() => facetBase.filter((f) => severities.size === 0 || severities.has(f.severity)), [facetBase, severities]);
  const moduleCounts = useMemo(() => Object.fromEntries(MODULES.map((m) => [m, findings.filter((f) => f.source_modules.includes(m)).length])) as Record<ModuleName, number>, [findings]);

  const selected = visible.find((f) => f.id === selectedId) ?? (narrow ? null : visible[0] ?? null);
  const showDetail = narrow ? detailOpen && selected !== null : true;
  const filtered = severities.size > 0 || module !== 'all' || query.trim() !== '';

  useEffect(() => {
    // After the shell's scroll-to-top on navigation, bring a restored selection back into view.
    const frame = requestAnimationFrame(() => {
      if (narrow && showDetail) detailRef.current?.scrollIntoView({ block: 'start' });
      else if (!narrow && selectedId) itemFor(selectedId)?.scrollIntoView({ block: 'nearest' });
    });
    return () => cancelAnimationFrame(frame);
  }, [narrow, showDetail, selectedId]);

  function itemFor(id: string) {
    return Array.from(listRef.current?.querySelectorAll<HTMLElement>('[data-id]') ?? []).find((item) => item.dataset.id === id) ?? null;
  }

  function toggleSeverity(severity: Severity) {
    const next = new Set(severities);
    if (next.has(severity)) next.delete(severity);
    else next.add(severity);
    setSeverities(next);
  }

  function clearFilters() {
    setSeverities(new Set());
    setModule('all');
    setQuery('');
  }

  function select(id: string) {
    onUiChange({ selectedId: id, detailOpen: true });
  }

  function back() {
    onUiChange({ detailOpen: false });
    requestAnimationFrame(() => (selectedId ? itemFor(selectedId) : null)?.focus());
  }

  const running = scan?.status === 'running';
  let empty: ReactNode = null;
  if (!scan) empty = <EmptyState icon={ListChecks} title="No findings yet">Findings appear here, with their evidence, as soon as each module reports.</EmptyState>;
  else if (findings.length === 0 && running) empty = <EmptyState icon={Hourglass} title="Scanning…">Findings appear as each module finishes.</EmptyState>;
  else if (findings.length === 0) empty = <EmptyState icon={CheckCircle2} title="No issues found">None of the modules that ran reported an issue. Analytics shows what was checked, skipped or failed.</EmptyState>;

  return (
    <Panel
      title="Observations"
      description={scan ? `${findings.length} found${running ? ' so far' : ''} · sorted by severity · select one to see its artifacts` : 'Evidence-backed issues from the latest scan.'}
      className="findings-panel"
    >
      {empty ?? (
        <>
          <div className="toolbar" role="search">
            <div className="chip-row" role="group" aria-label="Filter by severity">
              <button type="button" className="chip" aria-pressed={severities.size === 0} onClick={() => setSeverities(new Set())}>
                All <span className="badge-count">{facetBase.length}</span>
              </button>
              {SEVERITIES.map((severity) => {
                const count = facetBase.filter((f) => f.severity === severity).length;
                return (
                  <button
                    key={severity}
                    type="button"
                    className="chip"
                    data-severity={severity}
                    aria-pressed={severities.has(severity)}
                    disabled={count === 0 && !severities.has(severity)}
                    onClick={() => toggleSeverity(severity)}
                  >
                    {SEVERITY_META[severity].label} <span className="badge-count">{count}</span>
                  </button>
                );
              })}
            </div>
            <div className="toolbar-row">
              <label className="inline-field">
                <span className="visually-hidden">Module</span>
                <select value={module} onChange={(event) => setModule(event.target.value as ModuleName | 'all')}>
                  <option value="all">All modules</option>
                  {MODULES.map((m) => (
                    <option key={m} value={m}>
                      {MODULE_META[m].label} ({moduleCounts[m]})
                    </option>
                  ))}
                </select>
              </label>
              <label className="inline-field search-field">
                <Search size={16} aria-hidden="true" />
                <span className="visually-hidden">Search findings</span>
                <input type="search" value={query} placeholder="Search title, file or URL" onChange={(event) => setQuery(event.target.value)} />
              </label>
            </div>
          </div>

          <div className="findings-layout" data-view={narrow && showDetail ? 'detail' : 'list'}>
            <div className="findings-list-pane">
              {visible.length === 0 ? (
                <EmptyState icon={FilterX} title="No findings match these filters">
                  <button type="button" className="link-button" onClick={clearFilters}>
                    Clear filters
                  </button>
                </EmptyState>
              ) : (
                <ul ref={listRef} className="finding-list" role="list" aria-label="Findings">
                  {visible.map((finding) => (
                    <li key={finding.id}>
                      <button
                        type="button"
                        data-id={finding.id}
                        className="finding-item"
                        aria-current={selected?.id === finding.id ? 'true' : undefined}
                        onClick={() => select(finding.id)}
                      >
                        <span className="finding-item-top">
                          <SeverityBadge severity={finding.severity} />
                          {finding.verification === 'hypothesis' && <span className="hint-tag">Hypothesis</span>}
                          {finding.review.decision !== 'pending' && <span className="hint-tag" data-decision={finding.review.decision}>{finding.review.decision}</span>}
                        </span>
                        <span className="finding-item-title">{finding.title}</span>
                        <span className="finding-item-meta">
                          <span className="break-anywhere">
                            {formatLocation(finding.location, scan?.target_url)}
                            {!finding.location.file && !finding.location.line_start && finding.location.element && ` · ${finding.location.element}`}
                          </span>
                          {finding.evidence.occurrences > 1 && <span> · ×{finding.evidence.occurrences}</span>}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              {filtered && visible.length > 0 && (
                <p className="muted small list-footer">
                  Showing {visible.length} of {findings.length} ·{' '}
                  <button type="button" className="link-button" onClick={clearFilters}>
                    Clear filters
                  </button>
                </p>
              )}
            </div>
            {showDetail && selected && (
              <div className="findings-detail-pane" ref={detailRef}>
                <FindingDetail key={selected.id} finding={selected} baseUrl={scan?.target_url} onUpdated={onFindingUpdated} onBack={narrow ? back : undefined} />
              </div>
            )}
          </div>
        </>
      )}
    </Panel>
  );
}
