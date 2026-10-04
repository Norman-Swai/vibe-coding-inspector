import { Globe, Laptop, Play } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import type { InspectionMode, ScanRequest } from '../contracts/finding';
import { useSettings } from '../lib/settings';
import { ErrorNotice, Field, Panel, SegmentedControl } from './ui';

const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

export function validateTarget(url: string, mode: InspectionMode): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url.trim());
  } catch {
    return 'Enter a full URL, for example http://localhost:3000.';
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return 'Only http:// and https:// URLs can be inspected.';
  if (mode === 'localhost' && !LOCAL_HOSTS.includes(parsed.hostname)) return 'Localhost mode only accepts localhost, 127.0.0.1 or [::1]. Switch to Public site for other hosts.';
  return null;
}

export function validateRepoPath(path: string): string | null {
  const value = path.trim();
  if (!value) return null;
  return value.startsWith('/') || /^[A-Za-z]:[\\/]/.test(value) ? null : 'Use an absolute path, for example /home/me/my-app.';
}

/** The form's contents. Owned by the app shell so they survive switching views while a scan runs. */
export interface LaunchDraft {
  mode: InspectionMode;
  targetUrl: string;
  repoPath: string;
  authorized: boolean;
}

export const EMPTY_DRAFT: LaunchDraft = { mode: 'localhost', targetUrl: 'http://localhost:3000', repoPath: '', authorized: false };

export function LaunchPanel({
  draft,
  onDraftChange,
  busy,
  running,
  error,
  onStart,
}: {
  draft: LaunchDraft;
  onDraftChange: (patch: Partial<LaunchDraft>) => void;
  busy: boolean;
  running: boolean;
  error: string | null;
  onStart: (request: ScanRequest) => void;
}) {
  const { settings, open } = useSettings();
  const { mode, targetUrl, repoPath, authorized } = draft;
  const setMode = (value: InspectionMode) => onDraftChange({ mode: value });
  const setTargetUrl = (value: string) => onDraftChange({ targetUrl: value });
  const setRepoPath = (value: string) => onDraftChange({ repoPath: value });
  const setAuthorized = (value: boolean) => onDraftChange({ authorized: value });
  const [submitted, setSubmitted] = useState(false);

  const targetError = validateTarget(targetUrl, mode);
  const repoError = mode === 'localhost' ? validateRepoPath(repoPath) : null;
  const canSubmit = !targetError && !repoError && authorized && !busy && !running;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || running) return;
    setSubmitted(true);
    if (!canSubmit) return;
    onStart({
      target_url: targetUrl.trim(),
      repo_path: mode === 'localhost' && repoPath.trim() ? repoPath.trim() : undefined,
      authorization_confirmed: authorized,
      inspection_mode: mode,
      max_pages: settings.maxPages,
      timeout_seconds: settings.timeoutSeconds,
    });
  }

  return (
    <Panel title="Target" description="Point the inspector at a running app you are allowed to test." className="launch-panel">
      <form className="form" onSubmit={submit} noValidate>
        <SegmentedControl
          label="Mode"
          value={mode}
          onChange={setMode}
          hint={
            mode === 'localhost'
              ? 'Crawls your local app and can also read its source code.'
              : 'Passive, read-only checks of a public page. Respects robots.txt; source code is not read.'
          }
          options={[
            { value: 'localhost', label: 'Localhost', icon: Laptop },
            { value: 'public-readonly', label: 'Public site', icon: Globe },
          ]}
        />

        <Field label="Target URL" error={submitted || targetUrl ? targetError : null}>
          {(props) => (
            <input
              {...props}
              type="url"
              inputMode="url"
              autoComplete="url"
              spellCheck={false}
              value={targetUrl}
              placeholder={mode === 'localhost' ? 'http://localhost:3000' : 'https://example.com'}
              onChange={(event) => setTargetUrl(event.target.value)}
            />
          )}
        </Field>

        {mode === 'localhost' && (
          <Field label="Repository path (optional)" hint="Absolute path to the app's source. Enables static analysis, secret scanning and npm audit." error={repoError}>
            {(props) => (
              <input
                {...props}
                autoComplete="off"
                spellCheck={false}
                value={repoPath}
                placeholder="/absolute/path/to/repo"
                onChange={(event) => setRepoPath(event.target.value)}
              />
            )}
          </Field>
        )}

        <label className="checkbox">
          <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
          <span>I own this app or I am authorised to inspect it.</span>
        </label>
        {submitted && !authorized && <p className="field-error">Confirm that you are authorised before scanning.</p>}

        <div className="form-footer">
          <p className="muted small">
            Limits: {settings.maxPages} pages · {settings.timeoutSeconds} s timeout{' '}
            <button type="button" className="link-button" onClick={() => open('scan')}>
              Change
            </button>
          </p>
          {/* aria-disabled, not disabled: a disabled button drops keyboard focus to <body> mid-scan. */}
          <button type="submit" className="button button-primary" aria-disabled={!canSubmit}>
            {running ? <span className="spinner" aria-hidden="true" /> : <Play size={16} aria-hidden="true" />}
            {busy ? 'Starting…' : running ? 'Scan in progress…' : 'Start scan'}
          </button>
        </div>
        {error && <ErrorNotice>{error}</ErrorNotice>}
      </form>
    </Panel>
  );
}
