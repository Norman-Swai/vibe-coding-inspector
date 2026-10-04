import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, apiClient } from '../api/client';
import type { ActivityEvent, ActivityPage, Finding, ScanStatusResponse } from '../contracts/finding';
import { MODULES } from '../lib/meta';

export const POLL_INTERVAL_MS = 800;
const MAX_BACKOFF_MS = 10_000;

function message(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Polls one scan until it completes, then stops.
 * - Findings are only re-fetched when the status shows that something changed.
 * - The activity log is fetched incrementally (?since=) whenever the status reports new events.
 * - A poll that started before a local review update never overwrites it.
 * - Status, activity and findings from one poll are applied together, so counts, logs and lists always agree.
 * - If the backend no longer knows the scan (e.g. it restarted), polling stops and onMissing is called with a message.
 */
export const MISSING_SCAN_MESSAGE = 'The previous scan is no longer available (the inspector API was probably restarted). Start a new scan.';

/** Why a status response cannot be used by this UI (e.g. it came from an older backend), or null if it is fine. */
export function statusIncompatibility(status: unknown): string | null {
  const value = (status ?? {}) as Partial<ScanStatusResponse>;
  const missing: string[] = (['status', 'options', 'modules', 'summary', 'activity_count'] as const).filter((key) => value[key] === undefined || value[key] === null);
  if (value.modules) missing.push(...MODULES.filter((module) => !value.modules?.[module]?.state).map((module) => `modules.${module}`));
  return missing.length ? `missing ${missing.join(', ')}` : null;
}

export function useScan(scanId: string | null, onMissing?: (message: string) => void) {
  const [scan, setScan] = useState<ScanStatusResponse | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [activity, setActivity] = useState<ActivityEvent[]>([]);
  const [activityDropped, setActivityDropped] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const localEdits = useRef(0);
  const missingRef = useRef(onMissing);
  missingRef.current = onMissing;

  useEffect(() => {
    setScan(null);
    setFindings([]);
    setActivity([]);
    setActivityDropped(0);
    setError(null);
    if (!scanId) return;

    let cancelled = false;
    let timer: number | undefined;
    let syncedSignature = '';
    let nextSeq = 0;
    let knownEvents = 0;
    let failures = 0;

    const tick = async () => {
      const editsAtStart = localEdits.current;
      try {
        const status = await apiClient.getScan(scanId);
        if (cancelled) return;
        const incompatible = statusIncompatibility(status);
        if (incompatible) {
          // Rendering this would crash the views; forget the scan and say why instead.
          missingRef.current?.(
            `The inspector API returned this scan in an older format (${incompatible}). Restart the backend from this checkout, then start a new scan.`,
          );
          return;
        }
        let page: ActivityPage | null = null;
        if (status.activity_count > knownEvents) {
          page = await apiClient.getActivity(scanId, nextSeq);
          if (cancelled) return;
        }
        const signature = `${status.status}|${status.summary.total_findings}|${Object.values(status.module_status).join(',')}`;
        let list: Finding[] | null = null;
        if (signature !== syncedSignature) {
          list = await apiClient.getFindings(scanId);
          if (cancelled) return;
        }

        // Apply everything from this poll in one render (React batches these synchronous updates).
        setScan(status);
        if (page) {
          const fresh = page.events;
          if (fresh.length) setActivity((current) => [...current, ...fresh]);
          nextSeq = page.next_seq;
          knownEvents = page.next_seq + page.dropped;
          setActivityDropped(page.dropped);
        }
        if (list && localEdits.current === editsAtStart) {
          setFindings(list);
          syncedSignature = signature;
        }
        failures = 0;
        setError(null);
        const settled = status.status === 'completed' && signature === syncedSignature && knownEvents >= status.activity_count;
        if (!settled) timer = window.setTimeout(tick, POLL_INTERVAL_MS);
      } catch (pollError) {
        if (cancelled) return;
        if (pollError instanceof ApiError && pollError.status === 404) {
          // The caller owns the message: this hook's state is reset as soon as the scan id is cleared.
          missingRef.current?.(MISSING_SCAN_MESSAGE);
          return;
        }
        failures += 1;
        setError(`Lost contact with the inspector API (${message(pollError)}). Retrying…`);
        timer = window.setTimeout(tick, Math.min(MAX_BACKOFF_MS, POLL_INTERVAL_MS * 2 ** failures));
      }
    };

    void tick();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [scanId]);

  const replaceFinding = useCallback((updated: Finding) => {
    localEdits.current += 1;
    setFindings((current) => current.map((finding) => (finding.id === updated.id ? updated : finding)));
  }, []);

  return { scan, findings, activity, activityDropped, error, replaceFinding };
}
