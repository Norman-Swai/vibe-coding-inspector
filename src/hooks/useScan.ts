import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../api/client';
import type { Finding, ScanStatusResponse } from '../contracts/finding';

export const POLL_INTERVAL_MS = 800;
const MAX_BACKOFF_MS = 10_000;

function message(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Polls one scan until it completes, then stops. Findings are only re-fetched when the status shows
 * that something changed, and a poll that started before a local review update never overwrites it.
 */
export function useScan(scanId: string | null) {
  const [scan, setScan] = useState<ScanStatusResponse | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const localEdits = useRef(0);

  useEffect(() => {
    setScan(null);
    setFindings([]);
    setError(null);
    if (!scanId) return;

    let cancelled = false;
    let timer: number | undefined;
    let syncedSignature = '';
    let failures = 0;

    const tick = async () => {
      const editsAtStart = localEdits.current;
      try {
        const status = await apiClient.getScan(scanId);
        if (cancelled) return;
        setScan(status);
        const signature = `${status.status}|${status.summary.total_findings}|${Object.values(status.module_status).join(',')}`;
        if (signature !== syncedSignature) {
          const list = await apiClient.getFindings(scanId);
          if (cancelled) return;
          if (localEdits.current === editsAtStart) {
            setFindings(list);
            syncedSignature = signature;
          }
        }
        failures = 0;
        setError(null);
        if (status.status === 'running' || signature !== syncedSignature) timer = window.setTimeout(tick, POLL_INTERVAL_MS);
      } catch (pollError) {
        if (cancelled) return;
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

  return { scan, findings, error, replaceFinding };
}
