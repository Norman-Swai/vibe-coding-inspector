import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  FileCode2,
  Info,
  type LucideIcon,
  Scale,
  ShieldAlert,
  SignalHigh,
  SignalLow,
} from 'lucide-react';
import type { FileLocation, ModuleName, ModuleState, Severity } from '../contracts/finding';

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

export const MODULE_META: Record<ModuleName, { label: string; icon: LucideIcon; summary: string }> = {
  runtime: { label: 'Runtime', icon: Activity, summary: 'Crawls the site: broken links, error pages, accessibility basics' },
  static: { label: 'Static code', icon: FileCode2, summary: 'Reads the repository: missing imports, leaks, leftovers' },
  security: { label: 'Security', icon: ShieldAlert, summary: 'Headers, cookies, secrets, risky code, vulnerable packages' },
  compliance: { label: 'Compliance', icon: Scale, summary: 'Privacy, terms, contact and cookie-consent requirements' },
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

export function redactSecrets(text: string): string {
  return SECRET_SHAPES.reduce((value, pattern) => value.replace(pattern, (match) => `${match.slice(0, 3)}•••••• [${match.length} chars]`), text);
}
