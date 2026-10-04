import { Download, ScrollText, Search } from 'lucide-react';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ActivityEvent, ActivityKind, ModuleName } from '../contracts/finding';
import { ACTIVITY_KIND_META, formatOffset, MODULE_META, MODULES, redactSecrets, SHARED_SOURCE_LABEL } from '../lib/meta';
import { EmptyState, Panel, SegmentedControl } from './ui';

type KindFilter = 'all' | 'request' | 'check' | 'command' | 'problem';
type SourceFilter = 'all' | 'shared' | ModuleName;

const KIND_FILTERS: Record<KindFilter, (kind: ActivityKind) => boolean> = {
  all: () => true,
  request: (kind) => kind === 'request',
  check: (kind) => kind === 'check',
  command: (kind) => kind === 'command',
  problem: (kind) => kind === 'warning' || kind === 'error',
};

export function sourceLabel(module: ModuleName | null) {
  return module ? MODULE_META[module].label : SHARED_SOURCE_LABEL;
}

export function activityAsText(events: ActivityEvent[]) {
  return events
    .map((event) => {
      const head = `${formatOffset(event.at_ms).padStart(9)}  ${sourceLabel(event.module).padEnd(15)} ${event.kind.padEnd(8)} ${event.message}`;
      const output = event.output ? `\n${redactSecrets(event.output).replace(/^/gm, '             │ ')}` : '';
      return head + output;
    })
    .join('\n');
}

function matches(event: ActivityEvent, query: string) {
  if (!query) return true;
  const haystack = `${event.message} ${event.output ?? ''} ${event.request?.url ?? ''}`.toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .every((word) => haystack.includes(word));
}

/** Chronological log of everything the inspector did, with the output of each check and command. */
export function ActivityLog({
  events,
  dropped,
  running,
  initialQuery = '',
  onDownload,
}: {
  events: ActivityEvent[];
  dropped: number;
  running: boolean;
  initialQuery?: string;
  onDownload: () => void;
}) {
  const [kind, setKind] = useState<KindFilter>('all');
  const [source, setSource] = useState<SourceFilter>('all');
  const [query, setQuery] = useState(initialQuery);
  const listRef = useRef<HTMLOListElement>(null);
  const followRef = useRef(true);

  useEffect(() => setQuery(initialQuery), [initialQuery]);

  const visible = useMemo(
    () =>
      events.filter(
        (event) =>
          KIND_FILTERS[kind](event.kind) &&
          (source === 'all' || (source === 'shared' ? event.module === null : event.module === source)) &&
          matches(event, query.trim()),
      ),
    [events, kind, source, query],
  );

  // Keep the newest event in view while the scan runs, unless the reader has scrolled up.
  useLayoutEffect(() => {
    const list = listRef.current;
    if (list && running && followRef.current) list.scrollTop = list.scrollHeight;
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
          onChange={setKind}
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
            <select value={source} onChange={(event) => setSource(event.target.value as SourceFilter)}>
              <option value="all">All sources</option>
              <option value="shared">{SHARED_SOURCE_LABEL}</option>
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
            <input type="search" value={query} placeholder="Search messages, URLs, output" onChange={(event) => setQuery(event.target.value)} />
          </label>
        </div>
      </div>

      {events.length === 0 ? (
        <EmptyState icon={ScrollText} title={running ? 'Waiting for the first events…' : 'No activity recorded'} />
      ) : visible.length === 0 ? (
        <EmptyState icon={ScrollText} title="No events match these filters" />
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
                    <details className="activity-output" open={event.kind === 'command' || undefined}>
                      <summary>{event.kind === 'command' ? 'Command output' : 'Details'}</summary>
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
