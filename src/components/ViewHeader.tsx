import type { ReactNode } from 'react';

/** Title block at the top of each view. The heading receives focus after navigation so screen readers announce the new view. */
export function ViewHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="view-header">
      <div className="view-heading">
        <h1 tabIndex={-1} data-view-heading>
          {title}
        </h1>
        {description && <p className="muted">{description}</p>}
      </div>
      {actions && <div className="view-actions">{actions}</div>}
    </header>
  );
}
