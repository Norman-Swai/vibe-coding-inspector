import { createContext, type PropsWithChildren, useCallback, useContext, useEffect, useMemo, useState } from 'react';

export type ThemePreference = 'system' | 'light' | 'dark';
export type Density = 'comfortable' | 'compact';
export type MotionPreference = 'system' | 'reduced';

export interface Settings {
  theme: ThemePreference;
  density: Density;
  motion: MotionPreference;
  /** Recorded on every review decision. */
  reviewer: string;
  /** Sent with each scan; the backend enforces the same bounds (backend/schemas.py ScanOptions). */
  maxPages: number;
  timeoutSeconds: number;
}

export const SETTINGS_KEY = 'vci-settings-v1';
export const LIMITS = { maxPages: { min: 1, max: 50 }, timeoutSeconds: { min: 1, max: 60 } } as const;
export const DEFAULT_SETTINGS: Settings = {
  theme: 'system',
  density: 'comfortable',
  motion: 'system',
  reviewer: '',
  maxPages: 8,
  timeoutSeconds: 10,
};

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return allowed.includes(value as T) ? (value as T) : fallback;
}

function clamp(value: unknown, { min, max }: { min: number; max: number }, fallback: number): number {
  const number = typeof value === 'number' ? value : Number.parseFloat(String(value));
  return Number.isFinite(number) ? Math.min(max, Math.max(min, Math.round(number))) : fallback;
}

/** Accepts anything (stored JSON, form input) and returns valid settings. */
export function sanitizeSettings(raw: unknown): Settings {
  const value = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  return {
    theme: oneOf(value.theme, ['system', 'light', 'dark'], DEFAULT_SETTINGS.theme),
    density: oneOf(value.density, ['comfortable', 'compact'], DEFAULT_SETTINGS.density),
    motion: oneOf(value.motion, ['system', 'reduced'], DEFAULT_SETTINGS.motion),
    reviewer: typeof value.reviewer === 'string' ? value.reviewer.slice(0, 80) : DEFAULT_SETTINGS.reviewer,
    maxPages: clamp(value.maxPages, LIMITS.maxPages, DEFAULT_SETTINGS.maxPages),
    timeoutSeconds: clamp(value.timeoutSeconds, LIMITS.timeoutSeconds, DEFAULT_SETTINGS.timeoutSeconds),
  };
}

export function loadSettings(): Settings {
  try {
    const stored = window.localStorage.getItem(SETTINGS_KEY);
    return stored ? sanitizeSettings(JSON.parse(stored)) : DEFAULT_SETTINGS;
  } catch {
    return DEFAULT_SETTINGS;
  }
}

function saveSettings(settings: Settings) {
  try {
    window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
  } catch {
    // Storage can be unavailable (private mode, blocked site data); settings still apply for this visit.
  }
}

function prefersDark() {
  return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

/** Applies appearance settings to <html>. index.html runs the same logic before first paint to avoid a flash. */
export function applyAppearance(settings: Settings) {
  const root = document.documentElement;
  const theme = settings.theme === 'system' ? (prefersDark() ? 'dark' : 'light') : settings.theme;
  root.dataset.theme = theme;
  root.dataset.density = settings.density;
  root.dataset.motion = settings.motion;
  root.style.colorScheme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'dark' ? '#0f141b' : '#f6f7f9');
}

interface SettingsContextValue {
  settings: Settings;
  update: (patch: Partial<Settings>) => void;
  reset: () => void;
  isOpen: boolean;
  open: (section?: SettingsSection) => void;
  close: () => void;
  section: SettingsSection;
}

export type SettingsSection = 'appearance' | 'review' | 'scan';

const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: PropsWithChildren) {
  const [settings, setSettings] = useState<Settings>(loadSettings);
  const [isOpen, setOpen] = useState(false);
  const [section, setSection] = useState<SettingsSection>('appearance');

  useEffect(() => {
    applyAppearance(settings);
    saveSettings(settings);
    if (settings.theme !== 'system' || typeof window.matchMedia !== 'function') return;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const follow = () => applyAppearance(settings);
    media.addEventListener('change', follow);
    return () => media.removeEventListener('change', follow);
  }, [settings]);

  const update = useCallback((patch: Partial<Settings>) => setSettings((current) => sanitizeSettings({ ...current, ...patch })), []);
  const reset = useCallback(() => setSettings(DEFAULT_SETTINGS), []);
  const open = useCallback((target: SettingsSection = 'appearance') => {
    setSection(target);
    setOpen(true);
  }, []);
  const close = useCallback(() => setOpen(false), []);

  const value = useMemo(() => ({ settings, update, reset, isOpen, open, close, section }), [settings, update, reset, isOpen, open, close, section]);
  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings(): SettingsContextValue {
  const value = useContext(SettingsContext);
  if (!value) throw new Error('useSettings must be used inside <SettingsProvider>');
  return value;
}
