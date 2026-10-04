import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRightLeft,
  CircleCheck,
  CircleX,
  FileCode2,
  Footprints,
  Info,
  ListChecks,
  type LucideIcon,
  Scale,
  ShieldAlert,
  SignalHigh,
  SignalLow,
  SquareTerminal,
} from 'lucide-react';
import type { ActivityKind, FileLocation, ModuleName, ModuleState, Severity } from '../contracts/finding';

// Single source of labels and icons. Colours live in styles.css, keyed by data-severity / data-state.

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const MODULES: ModuleName[] = ['runtime', 'static', 'security', 'compliance'];

export const SEVERITY_META: Record<Severity, { label: string; icon: LucideIcon }> = {
  critical: { label: 'Critical', icon: AlertOctagon },
  high: { label: 'High', icon: AlertTriangle },
  medium: { label: 'Medium', icon: SignalHigh },
  low: { label: 'Low', icon: SignalLow },
  info: { label: 'Info', icon: Info },
};

export const MODULE_META: Record<ModuleName, { label: string; icon: LucideIcon; summary: string; checks: string[] }> = {
  runtime: {
    label: 'Runtime',
    icon: Activity,
    summary: 'Crawls the site: broken links, error pages, accessibility basics',
    checks: [
      'Broken links and error responses, with the page and HTML line that links to them',
      'Stack traces or raw error messages visible on a page',
      'Missing page title, language and mobile viewport',
      'Form fields without labels and images without alt text',
      'Insecure http:// resources on https:// pages',
    ],
  },
  static: {
    label: 'Static code',
    icon: FileCode2,
    summary: 'Reads the repository: missing imports, leaks, leftovers',
    checks: [
      'Imports that point to files that do not exist',
      'Timers started with setInterval and never cleared',
      'Event listeners added but never removed',
      'Leftover debugger statements and TODO/FIXME notes',
    ],
  },
  security: {
    label: 'Security',
    icon: ShieldAlert,
    summary: 'Headers, cookies, secrets, risky code, vulnerable packages',
    checks: [
      'Security headers (CSP, framing, nosniff, HSTS) and software versions leaked in headers',
      'Cookies without HttpOnly, SameSite or Secure',
      'Hard-coded API keys, tokens and private keys (values are masked)',
      'eval, unsanitised HTML injection, shell=True, disabled TLS checks, .env files not git-ignored',
      'Known-vulnerable npm packages via npm audit',
    ],
  },
  compliance: {
    label: 'Compliance',
    icon: Scale,
    summary: 'Privacy, terms, contact and cookie-consent requirements',
    checks: [
      'Links to a privacy policy, terms, contact details and an about page on any crawled page',
      'A cookie-consent mechanism when cookies or trackers are actually observed',
    ],
  },
};

/** Label for events not tied to one module: the shared HTTP client, crawler and repository index. */
export const SHARED_SOURCE_LABEL = 'Crawler & files';

export const ACTIVITY_KIND_META: Record<ActivityKind, { label: string; icon: LucideIcon }> = {
  step: { label: 'Step', icon: Footprints },
  request: { label: 'Request', icon: ArrowRightLeft },
  check: { label: 'Check', icon: ListChecks },
  command: { label: 'Command', icon: SquareTerminal },
  result: { label: 'Result', icon: CircleCheck },
  warning: { label: 'Warning', icon: AlertTriangle },
  error: { label: 'Error', icon: CircleX },
};

export const MODULE_STATE_LABEL: Record<ModuleState, string> = {
  queued: 'Queued',
  running: 'Running',
  done: 'Done',
  failed: 'Failed',
  skipped: 'Skipped',
};

export function compareSeverity(a: Severity, b: Severity) {
  return SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b);
}

/** "src/app.ts:12-14", "/about · line 3", or the full URL for other origins. */
export function formatLocation(location: FileLocation, baseUrl?: string): string {
  const lines = location.line_start
    ? location.line_end && location.line_end !== location.line_start
      ? `${location.line_start}-${location.line_end}`
      : `${location.line_start}`
    : '';
  if (location.file) return lines ? `${location.file}:${lines}` : location.file;
  if (location.url) {
    let url = location.url;
    try {
      const parsed = new URL(location.url);
      if (baseUrl && parsed.origin === new URL(baseUrl).origin) url = `${parsed.pathname}${parsed.search}`;
    } catch {
      // Keep the raw value.
    }
    return lines ? `${url} · line ${lines}` : url;
  }
  return 'Unknown location';
}

export function formatDuration(ms?: number | null): string {
  if (ms == null) return '';
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
}

export function formatBytes(bytes?: number | null): string {
  if (bytes == null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  return bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} kB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function formatOffset(ms: number): string {
  return `+${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

export function formatTime(iso?: string | null): string {
  if (!iso) return '';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

// Defence in depth: the backend masks secrets, but never render a credential-shaped string even if one slips through.
const SECRET_SHAPES = [
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g,
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/g,
  /\b[rs]k_live_[A-Za-z0-9]{20,}/g,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
];

// Values of URL query parameters whose names suggest a credential (?access_token=…, &api_key=…). Mirrors backend/analyzers/common.py.
const SECRET_QUERY_VALUE = /([?&;][\w.-]*(?:token|key|secret|passw(?:or)?d|pwd|auth|signature|sig|session|credential)[\w.-]*=)([^&#\s"'<>]{4,})/gi;

function mask(value: string) {
  return value.length <= 8 ? '••••••••' : `${value.slice(0, 3)}•••••• [${value.length} chars]`;
}

export function redactSecrets(text: string): string {
  const masked = SECRET_SHAPES.reduce((value, pattern) => value.replace(pattern, (match) => (match.includes('••••••') ? match : mask(match))), text);
  return masked.replace(SECRET_QUERY_VALUE, (_, name: string, value: string) => (value.includes('••••••') ? name + value : name + mask(value)));
}
