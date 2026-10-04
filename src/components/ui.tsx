import { PropsWithChildren } from 'react';

type PanelProps = PropsWithChildren<{
  className?: string;
  title?: string;
  subtitle?: string;
  action?: React.ReactNode;
}>;

export function Panel({ className = '', title, subtitle, action, children }: PanelProps) {
  return (
    <section className={`panel ${className}`.trim()}>
      {(title || subtitle || action) && (
        <div className="panel-header">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <p>{subtitle}</p>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function MetricCard({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="hero-metric-card branded-card">
      <span className="hero-metric-label">{label}</span>
      <strong>{value}</strong>
      {detail && <p className="metric-detail">{detail}</p>}
    </div>
  );
}
