import { ServerCrash } from 'lucide-react';
import type { BackendHealth } from '../hooks/useBackendHealth';

const START_COMMAND = 'uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000';

/** Shown on every view when the inspector API is missing or older than this UI, with the command that fixes it. */
export function BackendBanner({ health }: { health: BackendHealth }) {
  if (health.kind === 'ok' || health.kind === 'checking') return null;
  const outdated = health.kind === 'outdated';
  return (
    <div className="backend-banner" role="alert">
      <ServerCrash size={20} aria-hidden="true" />
      <div>
        <p className="backend-banner-title">
          {outdated ? 'The inspector API is an older version than this page' : 'The inspector API is not reachable'}
        </p>
        <p>
          {outdated
            ? `The backend answering on port 8000 is out of date: ${health.detail}. Stop it (Ctrl+C) and start it again from this checkout's folder:`
            : `Nothing is answering on 127.0.0.1:8000 (${health.detail}). Start the backend from this checkout's folder:`}
        </p>
        <pre className="evidence">{START_COMMAND}</pre>
        <p className="muted small">Scans cannot start until this is fixed. This message disappears by itself a few seconds after the backend is running.</p>
      </div>
    </div>
  );
}
