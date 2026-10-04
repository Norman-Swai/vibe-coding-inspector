import { Download, ScrollText, Search } from 'lucide-react';
import { useEffect, useLayoutEffect, useMemo, useRef } from 'react';
import type { ActivityEvent, ModuleName } from '../contracts/finding';
import { ACTIVITY_KIND_META, formatOffset, MODULE_META, MODULES, redactSecrets, SHARED_SOURCE_LABEL } from '../lib/meta';
import { EmptyState, Panel, SegmentedControl } from './ui';

export type KindFilter = 'all' | 'request' | 'check' | 'command' | 'problem';
/** "<module>+shared" is what a trace link selects: the module's events plus the shared work (crawl, requests) behind them. */
export type SourceFilter = 'all' | 'shared' | ModuleName | `${ModuleName}+shared`;

/** Filters. Owned by the app shell so they survive leaving Analytics and coming back. */
export interface ActivityUiState {
  kind: KindFilter;
  source: SourceFilter;
  query: string;
}

export const EMPTY_ACTIVITY_UI: ActivityUiState = { kind: 'all', source: 'all', query: '' };

/** A source filter from the route (#/analytics?source=…), or null when the value is not one. A module named there comes
 * from a trace link, whose evidence was produced by shared work as well, so both are shown. */
export function parseSource(value: string | null): SourceFilter | null {
  if (value === 'all' || value === 'shared') return value;
  return MODULES.includes(value as ModuleName) ? `${value as ModuleName}+shared` : null;
}

/** The module of a "<module>+shared" filter, or null for any other filter. */
export function moduleWithShared(source: SourceFilter): ModuleName | null {
  const module = source.endsWith('+shared') ? (source.slice(0, -'+shared'.length) as ModuleName) : null;
  return module && MODULES.includes(module) ? module : null;
}

/** Commands are logged as "$ <command> → …"; a failed run is an error event but is still a command. */
export function isCommand(event: ActivityEvent) {
  return event.kind === 'command' || event.message.startsWith('$ ');
}

const KIND_FILTERS: Record<KindFilter, (event: ActivityEvent) => boolean> = {
  all: () => true,
  request: (event) => event.kind === 'request',
  check: (event) => event.kind === 'check',
  command: isCommand,
  problem: (event) => event.kind === 'warning' || event.kind === 'error',
};

function fromSource(event: ActivityEvent, source: SourceFilter) {
  if (source === 'all') return true;
  if (source === 'shared') return event.module === null;
  const traced = moduleWithShared(source);
  if (traced) return event.module === traced || event.module === null;
  return event.module === source;
}

export function sourceLabel(module: ModuleName | null) {
  return module ? MODULE_META[module].label : SHARED_SOURCE_LABEL;
}

export function activityAsText(events: ActivityEvent[]) {
  return events
    .map((event) => {
      const head = `${formatOffset(event.at_ms).padStart(9)}  ${sourceLabel(event.module).padEnd(15)} ${event.kind.padEnd(8)} ${redactSecrets(event.message)}`;
      const output = event.output ? `\n${redactSecrets(event.output).replace(/^/gm, '             │ ')}` : '';
      return head + output;
    })
    .join('\n');
}

function escapeRegExp(text: string) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** A full URL matches whole: tracing "http://x/" must list the request for that page, not every request under http://x/. */
function matches(event: ActivityEvent, query: string) {
  if (!query) return true;
  const lowered = query.toLowerCase();
  const text = `${event.message} ${event.output ?? ''}`.toLowerCase();
  if (/^https?:\/\//.test(lowered)) {
    if (event.request?.url.toLowerCase() === lowered) return true;
    // The URL may be followed by punctuation (":", ")") but not by more path, query or fragment.
    return new RegExp(`${escapeRegExp(lowered)}(?![\\w/?#&=%+~-]|\\.\\S)`).test(text);
  }
  const haystack = `${text} ${event.request?.url.toLowerCase() ?? ''}`;
  return lowered.split(/\s+/).every((word) => haystack.includes(word));
}

/** Chronological log of everything the inspector did, with the output of each check and command. */
export function ActivityLog({
  events,
  dropped,
  running,
  ui,
  onUiChange,
  initialQuery = '',
  initialSource = null,
  onDownload,
}: {
  events: ActivityEvent[];
  dropped: number;
  running: boolean;
  ui: ActivityUiState;
  onUiChange: (patch: Partial<ActivityUiState>) => void;
  initialQuery?: string;
  initialSource?: SourceFilter | null;
  onDownload: () => void;
}) {
  const { kind, source, query } = ui;
  const listRef = useRef<HTMLOListElement>(null);
  const followRef = useRef(true);
  const wasRunning = useRef(running);

  // A trace link ("Trace in Analytics") sets the filters it needs; a plain visit keeps whatever was set before.
  useEffect(() => {
    if (initialQuery || initialSource) onUiChange({ kind: 'all', source: initialSource ?? 'all', query: initialQuery });
  }, [initialQuery, initialSource, onUiChange]);

  const visible = useMemo(() => events.filter((event) => KIND_FILTERS[kind](event) && fromSource(event, source) && matches(event, query.trim())), [events, kind, source, query]);

  // Keep the newest event in view while the scan runs (including the final batch that arrives with completion),
  // unless the reader has scrolled up.
  useLayoutEffect(() => {
    const list = listRef.current;
    if (list && (running || wasRunning.current) && followRef.current) list.scrollTop = list.scrollHeight;
    wasRunning.current = running;
  }, [visible.length, running]);

  const filtered = kind !== 'all' || source !== 'all' || query.trim() !== '';

  return (
    <Panel
      title="Activity"
      description="Every request, check and command the inspector ran, in order, with its output."
      className="activity-panel"
      actions={
        <button type="button" className="button button-ghost" onClick={onDownload} disabled={events.length === 0}>
          <Download size={16} aria-hidden="true" /> Download log
        </button>
      }
    >
      <div className="toolbar">
        <SegmentedControl
          label="Show"
          value={kind}
          onChange={(value) => onUiChange({ kind: value })}
          options={[
            { value: 'all', label: 'All' },
            { value: 'request', label: 'Requests' },
            { value: 'check', label: 'Checks' },
            { value: 'command', label: 'Commands' },
            { value: 'problem', label: 'Problems' },
          ]}
        />
        <div className="toolbar-row">
          <label className="inline-field">
            <span className="visually-hidden">Source</span>
            <select value={source} onChange={(event) => onUiChange({ source: event.target.value as SourceFilter })}>
              <option value="all">All sources</option>
              <option value="shared">{SHARED_SOURCE_LABEL}</option>
              {moduleWithShared(source) && (
                <option value={source}>
                  {MODULE_META[moduleWithShared(source)!].label} + {SHARED_SOURCE_LABEL.toLowerCase()}
                </option>
              )}
              {MODULES.map((module) => (
                <option key={module} value={module}>
                  {MODULE_META[module].label}
                </option>
              ))}
            </select>
          </label>
          <label className="inline-field search-field">
            <Search size={16} aria-hidden="true" />
            <span className="visually-hidden">Search activity</span>
            <input type="search" value={query} placeholder="Search activity" onChange={(event) => onUiChange({ query: event.target.value })} />
          </label>
        </div>
      </div>

      {events.length === 0 ? (
        <EmptyState icon={ScrollText} title={running ? 'Waiting for the first events…' : 'No activity recorded'} />
      ) : visible.length === 0 ? (
        kind === 'command' && !events.some(isCommand) ? (
          <EmptyState icon={ScrollText} title="No commands were run in this scan">
            The inspector runs one external command, <code>npm audit</code>, and only in Localhost mode with a repository that has a package-lock.json. Requests and
            checks are listed under their own filters.
          </EmptyState>
        ) : (
          <EmptyState icon={ScrollText} title="No events match these filters" />
        )
      ) : (
        <ol
          ref={listRef}
          className="activity-list"
          aria-label="Activity log"
          onScroll={(event) => {
            const list = event.currentTarget;
            followRef.current = list.scrollHeight - list.scrollTop - list.clientHeight < 40;
          }}
        >
          {visible.map((event) => {
            const { icon: Icon, label } = ACTIVITY_KIND_META[event.kind];
            return (
              <li key={event.seq} className="activity-item" data-kind={event.kind}>
                <span className="activity-time">{formatOffset(event.at_ms)}</span>
                <span className="activity-kind" title={label}>
                  <Icon size={14} aria-hidden="true" />
                  <span className="visually-hidden">{label}</span>
                </span>
                <div className="activity-body">
                  <p className="activity-message">
                    <span className="activity-source">{sourceLabel(event.module)}</span>
                    <span className="break-anywhere">{redactSecrets(event.message)}</span>
                  </p>
                  {event.output && (
                    <details className="activity-output" open={isCommand(event) || undefined}>
                      <summary>{isCommand(event) ? 'Command output' : 'Details'}</summary>
                      <pre className="evidence">{redactSecrets(event.output)}</pre>
                    </details>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}
      <p className="muted small list-footer">
        {filtered ? `Showing ${visible.length} of ${events.length} events` : `${events.length} events`}
        {dropped > 0 && ` · ${dropped} later events were not recorded (log limit reached)`}
        {running && ' · live'}
      </p>
    </Panel>
  );
}
