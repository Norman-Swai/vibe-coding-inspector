import { type LucideIcon } from 'lucide-react';
import { type ReactNode, useId } from 'react';
import type { ModuleState, Severity } from '../contracts/finding';
import { MODULE_STATE_LABEL, SEVERITY_META } from '../lib/meta';

// Shared building blocks. Every setting, filter and status chip in the app is built from these,
// so a control looks and behaves the same wherever it appears.

export function Panel({
  id,
  title,
  description,
  actions,
  className = '',
  children,
}: {
  id?: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  const headingId = useId();
  return (
    <section id={id} className={`panel ${className}`.trim()} aria-labelledby={headingId}>
      <header className="panel-header">
        <div className="panel-heading">
          <h2 id={headingId}>{title}</h2>
          {description && <p className="muted">{description}</p>}
        </div>
        {actions && <div className="panel-actions">{actions}</div>}
      </header>
      {children}
    </section>
  );
}

export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  const { label, icon: Icon } = SEVERITY_META[severity];
  return (
    <span className="badge" data-severity={severity}>
      <Icon size={14} aria-hidden="true" />
      {label}
      {count !== undefined && <span className="badge-count">{count}</span>}
    </span>
  );
}

export function StateBadge({ state }: { state: ModuleState }) {
  return (
    <span className="badge" data-state={state}>
      {state === 'running' && <span className="spinner" aria-hidden="true" />}
      {MODULE_STATE_LABEL[state]}
    </span>
  );
}

export function Tag({ children, tone = 'neutral', title }: { children: ReactNode; tone?: 'neutral' | 'warning' | 'success' | 'danger'; title?: string }) {
  return (
    <span className="badge" data-tone={tone} title={title}>
      {children}
    </span>
  );
}

export interface SegmentOption<T extends string> {
  value: T;
  label: string;
  icon?: LucideIcon;
}

/** Single-choice control built on native radio inputs (arrow keys, forms and screen readers work for free). */
export function SegmentedControl<T extends string>({
  label,
  value,
  options,
  onChange,
  hint,
}: {
  label: string;
  value: T;
  options: SegmentOption<T>[];
  onChange: (value: T) => void;
  hint?: string;
}) {
  const name = useId();
  const hintId = `${name}-hint`;
  return (
    <fieldset className="field segmented" aria-describedby={hint ? hintId : undefined}>
      <legend className="field-label">{label}</legend>
      <div className="segmented-track">
        {options.map(({ value: optionValue, label: optionLabel, icon: Icon }) => (
          <label key={optionValue} className="segmented-option">
            <input type="radio" name={name} value={optionValue} checked={value === optionValue} onChange={() => onChange(optionValue)} />
            <span>
              {Icon && <Icon size={16} aria-hidden="true" />}
              {optionLabel}
            </span>
          </label>
        ))}
      </div>
      {hint && (
        <p id={hintId} className="field-hint">
          {hint}
        </p>
      )}
    </fieldset>
  );
}

export interface FieldControlProps {
  id: string;
  'aria-describedby'?: string;
  'aria-invalid'?: boolean;
}

/** Label + control + hint + error, with ids wired for assistive technology. */
export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  children: (props: FieldControlProps) => ReactNode;
}) {
  const id = useId();
  const describedBy = [hint ? `${id}-hint` : '', error ? `${id}-error` : ''].filter(Boolean).join(' ') || undefined;
  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      {children({ id, 'aria-describedby': describedBy, 'aria-invalid': error ? true : undefined })}
      {hint && (
        <p id={`${id}-hint`} className="field-hint">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className="field-error">
          {error}
        </p>
      )}
    </div>
  );
}

export function EmptyState({ icon: Icon, title, children }: { icon: LucideIcon; title: string; children?: ReactNode }) {
  return (
    <div className="empty-state">
      <Icon size={28} aria-hidden="true" />
      <p className="empty-title">{title}</p>
      {children && <div className="muted">{children}</div>}
    </div>
  );
}

export function ErrorNotice({ children }: { children: ReactNode }) {
  return (
    <p className="notice" data-tone="danger" role="alert">
      {children}
    </p>
  );
}
