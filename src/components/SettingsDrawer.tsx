import { Monitor, Moon, RotateCcw, Sun, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { LIMITS, type SettingsSection, useSettings } from '../lib/settings';
import { Field, SegmentedControl } from './ui';

/** A number input that lets people clear and retype the value; it commits only valid numbers. */
function NumberSetting({
  label,
  hint,
  value,
  limits,
  unit,
  onCommit,
}: {
  label: string;
  hint: string;
  value: number;
  limits: { min: number; max: number };
  unit: string;
  onCommit: (value: number) => void;
}) {
  const [draft, setDraft] = useState(String(value));
  useEffect(() => setDraft(String(value)), [value]);
  const parsed = Number(draft);
  const valid = draft.trim() !== '' && Number.isInteger(parsed) && parsed >= limits.min && parsed <= limits.max;
  return (
    <Field label={label} hint={hint} error={valid ? null : `Enter a whole number from ${limits.min} to ${limits.max}.`}>
      {(props) => (
        <div className="input-with-unit">
          <input
            {...props}
            type="number"
            inputMode="numeric"
            min={limits.min}
            max={limits.max}
            step={1}
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value);
              const next = Number(event.target.value);
              if (event.target.value.trim() !== '' && Number.isInteger(next) && next >= limits.min && next <= limits.max) onCommit(next);
            }}
            onBlur={() => setDraft(String(value))}
          />
          <span className="unit" aria-hidden="true">
            {unit}
          </span>
        </div>
      )}
    </Field>
  );
}

const SECTION_IDS: Record<SettingsSection, string> = { appearance: 'settings-appearance', review: 'settings-review', scan: 'settings-scan' };

export function SettingsDrawer() {
  const { settings, update, reset, isOpen, close, section } = useSettings();
  const panelRef = useRef<HTMLDivElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    returnFocus.current = document.activeElement as HTMLElement | null;
    const target = panelRef.current?.querySelector<HTMLElement>(`#${SECTION_IDS[section]} input, #${SECTION_IDS[section]} button`);
    (target ?? panelRef.current)?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') close();
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      returnFocus.current?.focus?.();
    };
  }, [isOpen, section, close]);

  if (!isOpen) return null;

  return (
    <div className="drawer-root">
      <div className="drawer-backdrop" onClick={close} aria-hidden="true" />
      <div ref={panelRef} className="drawer" role="dialog" aria-modal="true" aria-labelledby="settings-title" tabIndex={-1}>
        <header className="drawer-header">
          <h2 id="settings-title">Settings</h2>
          <button type="button" className="icon-button" onClick={close} aria-label="Close settings">
            <X size={20} aria-hidden="true" />
          </button>
        </header>

        <div className="drawer-body">
          <section id={SECTION_IDS.appearance} className="settings-section" aria-labelledby="settings-appearance-title">
            <h3 id="settings-appearance-title">Appearance</h3>
            <SegmentedControl
              label="Theme"
              value={settings.theme}
              onChange={(theme) => update({ theme })}
              options={[
                { value: 'system', label: 'System', icon: Monitor },
                { value: 'light', label: 'Light', icon: Sun },
                { value: 'dark', label: 'Dark', icon: Moon },
              ]}
            />
            <SegmentedControl
              label="Density"
              value={settings.density}
              onChange={(density) => update({ density })}
              hint="Compact fits more findings on screen. Touch screens keep 44 px tap targets either way."
              options={[
                { value: 'comfortable', label: 'Comfortable' },
                { value: 'compact', label: 'Compact' },
              ]}
            />
            <SegmentedControl
              label="Motion"
              value={settings.motion}
              onChange={(motion) => update({ motion })}
              hint="Reduce turns off transitions and smooth scrolling."
              options={[
                { value: 'system', label: 'Follow system' },
                { value: 'reduced', label: 'Reduce' },
              ]}
            />
          </section>

          <section id={SECTION_IDS.review} className="settings-section" aria-labelledby="settings-review-title">
            <h3 id="settings-review-title">Review</h3>
            <Field label="Reviewer name" hint="Recorded with every confirm, reject, escalate and fix decision.">
              {(props) => (
                <input {...props} value={settings.reviewer} autoComplete="name" placeholder="e.g. Norman" onChange={(event) => update({ reviewer: event.target.value })} />
              )}
            </Field>
          </section>

          <section id={SECTION_IDS.scan} className="settings-section" aria-labelledby="settings-scan-title">
            <h3 id="settings-scan-title">Scan limits</h3>
            <p className="muted small">Applied to the next scan you start.</p>
            <NumberSetting
              label="Max pages to crawl"
              hint="Same-origin URLs the runtime crawler may request. Links beyond the limit are listed as not checked."
              value={settings.maxPages}
              limits={LIMITS.maxPages}
              unit="pages"
              onCommit={(maxPages) => update({ maxPages })}
            />
            <NumberSetting
              label="Request timeout"
              hint="How long to wait for each response before reporting it as failed."
              value={settings.timeoutSeconds}
              limits={LIMITS.timeoutSeconds}
              unit="seconds"
              onCommit={(timeoutSeconds) => update({ timeoutSeconds })}
            />
          </section>
        </div>

        <footer className="drawer-footer">
          <button type="button" className="button button-ghost" onClick={reset}>
            <RotateCcw size={16} aria-hidden="true" /> Reset to defaults
          </button>
          <button type="button" className="button button-primary" onClick={close}>
            Done
          </button>
        </footer>
      </div>
    </div>
  );
}
