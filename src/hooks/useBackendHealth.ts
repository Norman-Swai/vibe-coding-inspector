import { useEffect, useState } from 'react';
import { ApiError, apiClient, REQUIRED_API_VERSION } from '../api/client';

export type BackendHealth =
  | { kind: 'checking' }
  | { kind: 'ok'; version: string }
  | { kind: 'outdated'; detail: string }
  | { kind: 'unreachable'; detail: string };

export const HEALTH_RETRY_MS = 4000;

/**
 * Confirms the API behind /api is running and is the version this UI needs. Re-checks every few seconds until it is,
 * so the warning clears by itself once the backend is (re)started.
 */
export function useBackendHealth(): BackendHealth {
  const [health, setHealth] = useState<BackendHealth>({ kind: 'checking' });

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    const check = async () => {
      let next: BackendHealth;
      try {
        const body = await apiClient.health();
        next =
          typeof body.api_version === 'number' && body.api_version >= REQUIRED_API_VERSION
            ? { kind: 'ok', version: body.version }
            : { kind: 'outdated', detail: `it reports API version ${body.api_version ?? 'unknown'}; this UI needs ${REQUIRED_API_VERSION}` };
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) next = { kind: 'outdated', detail: 'it has no /api/health endpoint, so it predates this UI' };
        else if (error instanceof ApiError && error.status < 500) next = { kind: 'outdated', detail: `/api/health answered HTTP ${error.status}` };
        else next = { kind: 'unreachable', detail: error instanceof ApiError ? `the dev-server proxy answered HTTP ${error.status}` : 'the request failed' };
      }
      if (cancelled) return;
      setHealth(next);
      if (next.kind !== 'ok') timer = window.setTimeout(check, HEALTH_RETRY_MS);
    };

    void check();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, []);

  return health;
}
