import { AlertTriangle, CheckCircle2, FilterX, Hourglass, ListChecks, Search } from 'lucide-react';
import { type KeyboardEvent, type ReactNode, useEffect, useMemo, useRef } from 'react';
import type { Finding, ModuleName, ScanStatusResponse, Severity } from '../contracts/finding';
import { hrefFor, useHashRoute } from '../hooks/useHashRoute';
import { useMediaQuery } from '../hooks/useMediaQuery';
import { compareSeverity, formatLocation, listOf, MODULE_META, MODULES, SEVERITIES, SEVERITY_META } from '../lib/meta';
import { FindingDetail } from './FindingDetail';
import { EmptyState, Panel, SeverityBadge } from './ui';

const NARROW = '(max-width: 899px)';

/** Route parameter that opens a finding's full-screen detail on narrow screens: its own history entry, so Back closes it. */
export const DETAIL_PARAM = 'finding';
/** history.state of a detail entry that was pushed from the list, so "All findings" can go back instead of forward. */
const FROM_LIST_STATE = { findingDetailFromList: true };

function matchesQuery(finding: Finding, query: string) {
  if (!query) return true;
  const haystack = `${finding.title} ${finding.location.file ?? ''} ${finding.location.url ?? ''} ${finding.cwe_id ?? ''}`.toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .every((word) => haystack.includes(word));
}

/** Selection and filters. Owned by the app shell so they survive a round trip to Analytics ("Trace" then Back) and a reload. */
export interface FindingsUiState {
  severities: Severity[];
  module: ModuleName | 'all';
  query: string;
  selectedId: string | null;
}

export const EMPTY_FINDINGS_UI: FindingsUiState = { severities: [], module: 'all', query: '', selectedId: null };

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
  const { params, navigate } = useHashRoute();
  const { module, query, selectedId } = ui;
  const severities = useMemo(() => new Set(ui.severities), [ui.severities]);
  const setModule = (value: ModuleName | 'all') => onUiChange({ module: value });
  const setQuery = (value: string) => onUiChange({ query: value });
  const setSeverities = (value: Set<Severity>) => onUiChange({ severities: [...value] });
  const detailRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  // The list item to focus once the detail has closed (the item is hidden until then).
  const returnFocusTo = useRef<string | null>(null);

  const sorted = useMemo(() => [...findings].sort((a, b) => compareSeverity(a.severity, b.severity) || a.title.localeCompare(b.title)), [findings]);
  // Severity counts respect the other filters, so the chips always describe what clicking them would show.
  const facetBase = useMemo(() => sorted.filter((f) => (module === 'all' || f.source_modules.includes(module)) && matchesQuery(f, query.trim())), [sorted, module, query]);
  const visible = useMemo(() => facetBase.filter((f) => severities.size === 0 || severities.has(f.severity)), [facetBase, severities]);
  const moduleCounts = useMemo(() => Object.fromEntries(MODULES.map((m) => [m, findings.filter((f) => f.source_modules.includes(m)).length])) as Record<ModuleName, number>, [findings]);

  // On narrow screens the route says whether a detail is open (the list and the detail never share the screen there).
  const routeId = narrow ? params.get(DETAIL_PARAM) : null;
  const fromRoute = routeId ? (sorted.find((f) => f.id === routeId) ?? null) : null;
  const selected = fromRoute ?? visible.find((f) => f.id === selectedId) ?? (narrow ? null : (visible[0] ?? null));
  const showDetail = narrow ? fromRoute !== null : true;
  const filtered = severities.size > 0 || module !== 'all' || query.trim() !== '';
  // One tab stop for the whole list (arrow keys move within it), so Tab goes straight on to the detail.
  const currentId = selected?.id ?? selectedId;
  const tabStopId = visible.some((f) => f.id === currentId) ? currentId : (visible[0]?.id ?? null);

  useEffect(() => {
    // After the shell's scroll-to-top on navigation, bring a restored selection back into view. On narrow screens the
    // list (and the item that had focus) is hidden behind the detail, so the keyboard moves to the detail's heading.
    const frame = requestAnimationFrame(() => {
      if (narrow && showDetail) {
        detailRef.current?.scrollIntoView({ block: 'start' });
        detailRef.current?.querySelector<HTMLElement>('h3')?.focus({ preventScroll: true });
      } else if (narrow && returnFocusTo.current) {
        itemFor(returnFocusTo.current)?.focus();
        returnFocusTo.current = null;
      } else if (!narrow && selectedId) itemFor(selectedId)?.scrollIntoView({ block: 'nearest' });
    });
    return () => cancelAnimationFrame(frame);
  }, [narrow, showDetail, selectedId]);

  function items() {
    return Array.from(listRef.current?.querySelectorAll<HTMLElement>('[data-id]') ?? []);
  }

  function itemFor(id: string) {
    return items().find((item) => item.dataset.id === id) ?? null;
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
    onUiChange({ selectedId: id });
    if (!narrow) return;
    navigate('findings', { [DETAIL_PARAM]: id });
    window.history.replaceState(FROM_LIST_STATE, '');
  }

  function back() {
    returnFocusTo.current = selectedId;
    const state = window.history.state as { findingDetailFromList?: boolean } | null;
    if (state?.findingDetailFromList) window.history.back();
    else navigate('findings');
  }

  function onListKeyDown(event: KeyboardEvent<HTMLUListElement>) {
    const all = items();
    const index = all.indexOf(event.target as HTMLElement);
    if (index === -1) return;
    let next: number;
    if (event.key === 'ArrowDown') next = Math.min(all.length - 1, index + 1);
    else if (event.key === 'ArrowUp') next = Math.max(0, index - 1);
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = all.length - 1;
    else return;
    event.preventDefault();
    all[next].focus();
    // Wide screens show the focused item's detail alongside; narrow ones open it on Enter or a tap.
    const id = all[next].dataset.id;
    if (!narrow && id) onUiChange({ selectedId: id });
  }

  const running = scan?.status === 'running';
  const done = scan ? MODULES.filter((m) => scan.modules[m].state === 'done') : [];
  const notRun = MODULES.length - done.length;
  let empty: ReactNode = null;
  if (!scan) empty = <EmptyState icon={ListChecks} title="No findings yet">Findings appear here, with their evidence, as soon as each module reports.</EmptyState>;
  else if (findings.length === 0 && running) empty = <EmptyState icon={Hourglass} title="Scanning…">Findings appear as each module finishes.</EmptyState>;
  else if (findings.length === 0 && done.length === 0) {
    // "No issues" would be wrong: nothing was checked.
    empty = (
      <EmptyState icon={AlertTriangle} title="Nothing could be checked">
        Every module failed or was skipped, so this scan says nothing about the app. <a href={hrefFor('analytics')}>See why in Analytics</a>.
      </EmptyState>
    );
  } else if (findings.length === 0 && notRun > 0) {
    empty = (
      <EmptyState icon={AlertTriangle} title={`No issues found by ${listOf(done.map((m) => MODULE_META[m].label))}`}>
        {notRun} module{notRun === 1 ? '' : 's'} did not run, so {notRun === 1 ? 'its' : 'their'} checks are not reflected here.{' '}
        <a href={hrefFor('analytics')}>See why in Analytics</a>.
      </EmptyState>
    );
  } else if (findings.length === 0) {
    empty = <EmptyState icon={CheckCircle2} title="No issues found">Every module ran and none reported an issue. Analytics shows what was checked.</EmptyState>;
  }

  return (
    <Panel
      title="Observations"
      description={
        scan
          ? done.length === 0 && !running
            ? 'No module completed, so there is nothing to review.'
            : `${findings.length} found${running ? ' so far' : ''} · sorted by severity · select one to see its artifacts`
          : 'Evidence-backed issues from the latest scan.'
      }
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
                <ul ref={listRef} className="finding-list" role="list" aria-label="Findings" onKeyDown={onListKeyDown}>
                  {visible.map((finding) => (
                    <li key={finding.id}>
                      <button
                        type="button"
                        data-id={finding.id}
                        className="finding-item"
                        tabIndex={finding.id === tabStopId ? 0 : -1}
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
