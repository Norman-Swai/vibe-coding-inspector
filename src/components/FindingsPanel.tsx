import { CheckCircle2, FilterX, Hourglass, ListChecks, Search } from 'lucide-react';
import { type ReactNode, useEffect, useMemo, useRef, useState } from 'react';
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

export function FindingsPanel({
  scan,
  findings,
  onFindingUpdated,
}: {
  scan: ScanStatusResponse | null;
  findings: Finding[];
  onFindingUpdated: (finding: Finding) => void;
}) {
  const narrow = useMediaQuery(NARROW);
  const [severities, setSeverities] = useState<Set<Severity>>(new Set());
  const [module, setModule] = useState<ModuleName | 'all'>('all');
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
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
    if (narrow && showDetail) detailRef.current?.scrollIntoView({ block: 'start' });
  }, [narrow, showDetail, selectedId]);

  function toggleSeverity(severity: Severity) {
    setSeverities((current) => {
      const next = new Set(current);
      if (next.has(severity)) next.delete(severity);
      else next.add(severity);
      return next;
    });
  }

  function clearFilters() {
    setSeverities(new Set());
    setModule('all');
    setQuery('');
  }

  function select(id: string) {
    setSelectedId(id);
    setDetailOpen(true);
  }

  function back() {
    setDetailOpen(false);
    requestAnimationFrame(() => listRef.current?.querySelector<HTMLElement>(`[data-id="${selectedId}"]`)?.focus());
  }

  const running = scan?.status === 'running';
  let empty: ReactNode = null;
  if (!scan) empty = <EmptyState icon={ListChecks} title="No findings yet">Findings appear here, with their evidence, as soon as each module reports.</EmptyState>;
  else if (findings.length === 0 && running) empty = <EmptyState icon={Hourglass} title="Scanning…">Findings appear as each module finishes.</EmptyState>;
  else if (findings.length === 0) empty = <EmptyState icon={CheckCircle2} title="No issues found">None of the modules that ran reported an issue. Check Coverage for anything that was skipped or failed.</EmptyState>;

  return (
    <Panel
      id="findings"
      title="Findings"
      description={scan ? `${findings.length} found${running ? ' so far' : ''} · sorted by severity` : 'Evidence-backed issues from the latest scan.'}
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
