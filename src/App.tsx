import { FormEvent, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  FileSearch,
  Gauge,
  LayoutDashboard,
  Moon,
  Rocket,
  Scale,
  SearchCheck,
  Shield,
  Sparkles,
  Sun,
  WandSparkles,
  Zap,
} from 'lucide-react';
import { Area, AreaChart, CartesianGrid, Pie, PieChart, ResponsiveContainer, Tooltip, Cell } from 'recharts';
import { apiClient } from './api/client';
import type {
  Finding,
  FixReviewDecision,
  ModuleName,
  ReviewDecision,
  ScanRequest,
  ScanStatusResponse,
  Severity,
} from './contracts/finding';
import { MetricCard, Panel } from './components/ui';

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const categoryOrder: ModuleName[] = ['runtime', 'static', 'security', 'compliance'];

const moduleMeta: Record<ModuleName, { icon: typeof Activity; label: string; accent: string; color: string }> = {
  runtime: { icon: Activity, label: 'Runtime', accent: 'accent-runtime', color: '#38bdf8' },
  static: { icon: FileSearch, label: 'Static', accent: 'accent-static', color: '#818cf8' },
  security: { icon: Shield, label: 'Security', accent: 'accent-security', color: '#fb7185' },
  compliance: { icon: Scale, label: 'Compliance', accent: 'accent-compliance', color: '#34d399' },
};

const severityMeta: Record<Severity, { icon: typeof AlertTriangle; label: string; color: string }> = {
  critical: { icon: AlertTriangle, label: 'Critical', color: '#ef4444' },
  high: { icon: Zap, label: 'High', color: '#f97316' },
  medium: { icon: Gauge, label: 'Medium', color: '#f59e0b' },
  low: { icon: CheckCircle2, label: 'Low', color: '#3b82f6' },
  info: { icon: SearchCheck, label: 'Info', color: '#10b981' },
};

function isAllowedTarget(url: string, mode: ScanRequest['inspection_mode']) {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    if (mode === 'localhost') return ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
    return true;
  } catch {
    return false;
  }
}

function maskSecret(value?: string) {
  if (!value) return '';
  if (value.length <= 8) return '********';
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

export default function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const stored = typeof window !== 'undefined' ? window.localStorage.getItem('inspection-theme') : null;
    return stored === 'light' ? 'light' : 'dark';
  });
  const [density, setDensity] = useState<'comfortable' | 'compact'>(() => {
    const stored = typeof window !== 'undefined' ? window.localStorage.getItem('inspection-density') : null;
    return stored === 'compact' ? 'compact' : 'comfortable';
  });
  const [targetUrl, setTargetUrl] = useState('http://localhost:3000');
  const [repoPath, setRepoPath] = useState('');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [inspectionMode, setInspectionMode] = useState<ScanRequest['inspection_mode']>('localhost');
  const [scanId, setScanId] = useState<string | null>(null);
  const [scan, setScan] = useState<ScanStatusResponse | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [reviewReason, setReviewReason] = useState('');
  const [reviewer, setReviewer] = useState('analyst');
  const [error, setError] = useState<string | null>(null);
  const [exportMarkdown, setExportMarkdown] = useState('');
  const [loading, setLoading] = useState(false);

  const selectedFinding = findings.find((finding) => finding.id === selectedFindingId) ?? findings[0] ?? null;
  const targetValid = useMemo(() => isAllowedTarget(targetUrl, inspectionMode), [inspectionMode, targetUrl]);
  const repoValid = inspectionMode === 'public-readonly' || repoPath.startsWith('/');
  const formValid = targetValid && repoValid && authorizationConfirmed;

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.setAttribute('data-density', density);
    window.localStorage.setItem('inspection-theme', theme);
    window.localStorage.setItem('inspection-density', density);
    document.title = 'Vibe Coding Inspector';
  }, [theme, density]);

  useEffect(() => {
    if (!scanId) return;
    const poll = async () => {
      try {
        const [scanData, findingData] = await Promise.all([apiClient.getScan(scanId), apiClient.getFindings(scanId)]);
        setScan(scanData);
        setFindings(findingData);
        if (!selectedFindingId && findingData.length > 0) setSelectedFindingId(findingData[0].id);
      } catch (pollError) {
        setError(pollError instanceof Error ? pollError.message : 'Polling failed');
      }
    };
    void poll();
    const interval = setInterval(() => void poll(), 1500);
    return () => clearInterval(interval);
  }, [scanId, selectedFindingId]);

  const filteredFindings = useMemo(
    () => [...findings].sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)),
    [findings]
  );

  const severityCards = useMemo(
    () => severityOrder.map((severity) => ({ severity, count: scan?.summary.by_severity[severity] ?? 0, ...severityMeta[severity] })),
    [scan]
  );

  const categoryCards = useMemo(
    () => categoryOrder.map((category) => ({ category, count: scan?.summary.by_category[category] ?? 0, ...moduleMeta[category] })),
    [scan]
  );

  const trendData = useMemo(
    () => severityCards.map((card, index) => ({ name: card.label, value: card.count, trend: Math.max(card.count + (index % 2 === 0 ? 1 : 0), 0) })),
    [severityCards]
  );

  async function handleStartScan(event: FormEvent) {
    event.preventDefault();
    if (!formValid) return;
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.startScan({
        target_url: targetUrl,
        repo_path: repoPath || undefined,
        authorization_confirmed: authorizationConfirmed,
        inspection_mode: inspectionMode,
      });
      setScanId(response.scan_id);
      setExportMarkdown('');
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : 'Unable to start scan');
    } finally {
      setLoading(false);
    }
  }

  async function updateReview(decision: ReviewDecision) {
    if (!selectedFinding) return;
    if ((decision === 'rejected' || decision === 'escalated') && !reviewReason.trim()) {
      setError('Reject and escalate require a reason.');
      return;
    }
    const updated = await apiClient.updateReview(selectedFinding.id, {
      decision,
      reason: reviewReason.trim() || undefined,
      reviewer,
      timestamp: new Date().toISOString(),
    });
    setFindings((current) => current.map((finding) => (finding.id === updated.id ? updated : finding)));
    setError(null);
  }

  async function updateFixReview(decision: FixReviewDecision) {
    if (!selectedFinding) return;
    const updated = await apiClient.updateFixReview(selectedFinding.id, {
      decision,
      reviewer,
      timestamp: new Date().toISOString(),
    });
    setFindings((current) => current.map((finding) => (finding.id === updated.id ? updated : finding)));
  }

  async function handleExport() {
    if (!scanId) return;
    setExportMarkdown(await apiClient.getReport(scanId, 'markdown'));
  }

  return (
    <div className="app-shell">
      <aside className="sidebar-panel">
        <div className="sidebar-brand">
          <div className="brand-mark"><WandSparkles size={20} /></div>
          <div>
            <strong>Vibe Coding Inspector</strong>
            <p>Premium website assurance workspace</p>
          </div>
        </div>

        <nav className="sidebar-nav" aria-label="Dashboard sections">
          <a className="nav-item active" href="#overview"><LayoutDashboard size={18} /> Overview</a>
          <a className="nav-item" href="#launch"><Rocket size={18} /> Launch</a>
          <a className="nav-item" href="#analytics"><Gauge size={18} /> Analytics</a>
          <a className="nav-item" href="#findings"><AlertTriangle size={18} /> Findings</a>
          <a className="nav-item" href="#reports"><ArrowUpRight size={18} /> Reports</a>
        </nav>

        <div className="sidebar-control-group">
          <span className="control-label">Theme</span>
          <div className="theme-switcher" role="group" aria-label="Theme selection">
            <button type="button" className={theme === 'light' ? 'theme-button active' : 'theme-button'} onClick={() => setTheme('light')}><Sun size={16} /> Light</button>
            <button type="button" className={theme === 'dark' ? 'theme-button active' : 'theme-button'} onClick={() => setTheme('dark')}><Moon size={16} /> Dark</button>
          </div>
        </div>

        <div className="sidebar-control-group">
          <span className="control-label">Density</span>
          <div className="theme-switcher" role="group" aria-label="Density selection">
            <button type="button" className={density === 'comfortable' ? 'theme-button active' : 'theme-button'} onClick={() => setDensity('comfortable')}>Comfortable</button>
            <button type="button" className={density === 'compact' ? 'theme-button active' : 'theme-button'} onClick={() => setDensity('compact')}>Compact</button>
          </div>
        </div>
      </aside>

      <div className="main-shell">
        <header className="page-header" id="overview">
          <div className="hero-card micro-glow">
            <div>
              <span className="hero-kicker"><Sparkles size={14} /> Inspection console</span>
              <h1>Vibe Coding Inspector</h1>
              <p>
                A premium assurance dashboard for runtime, static, security, and compliance inspections with executive-grade visibility, reviewer control, and visual excellence.
              </p>
              <div className="hero-metrics">
                <MetricCard label="Coverage" value={`${scan ? Object.values(scan.module_status).filter((value) => value === 'done').length : 0}/4 modules`} detail="Completed inspection streams" />
                <MetricCard label="Findings" value={`${scan?.summary.total_findings ?? 0} observations`} detail="Evidence-backed inspection items" />
                <MetricCard label="Mode" value={inspectionMode === 'localhost' ? 'Authorized localhost' : 'Public readonly'} detail="Scope-aware inspection posture" />
              </div>
            </div>

            <div className="hero-visual-panel branded-card">
              <div className="hero-visual-header"><Gauge size={18} /> Severity trend</div>
              <div className="chart-shell">
                <ResponsiveContainer width="100%" height={180}>
                  <AreaChart data={trendData}>
                    <defs>
                      <linearGradient id="severityGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.85} />
                        <stop offset="95%" stopColor="#2563eb" stopOpacity={0.08} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.18)" />
                    <Tooltip contentStyle={{ borderRadius: 14, border: '1px solid rgba(148,163,184,0.18)' }} />
                    <Area type="monotone" dataKey="trend" stroke="#38bdf8" strokeWidth={3} fill="url(#severityGradient)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </header>

        <main className="layout-grid">
          <Panel className="span-8 micro-float" title="Launch inspection" subtitle="Choose the inspection mode, target, repository path, and authorization gate." action={<Rocket className="panel-header-icon" size={22} />}>
            <form onSubmit={handleStartScan} className="stack" id="launch">
              <div className="form-grid">
                <label>
                  Inspection mode
                  <select value={inspectionMode} onChange={(event) => setInspectionMode(event.target.value as ScanRequest['inspection_mode'])}>
                    <option value="localhost">Authorized localhost scan</option>
                    <option value="public-readonly">Public webpage readonly inspection</option>
                  </select>
                </label>

                <label>
                  Target URL
                  <input value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="http://localhost:3000" />
                </label>

                <label className="full-width">
                  Repository path
                  <input value={repoPath} onChange={(event) => setRepoPath(event.target.value)} placeholder="/absolute/path/to/repo" />
                </label>
              </div>

              {!targetValid && <p className="error-text">Enter a valid URL for the selected mode.</p>}
              {!repoValid && <p className="error-text">Repository path must be absolute unless using public-readonly mode.</p>}

              <label className="checkbox-row">
                <input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} />
                I own this app or I am authorized to inspect it.
              </label>

              <div className="button-row">
                <button type="submit" disabled={!formValid || loading}>{loading ? 'Starting…' : 'Start inspection'}</button>
              </div>
            </form>
            {error && <pre className="error-box">{error}</pre>}
          </Panel>

          <Panel className="span-4" title="Executive view" subtitle="Quick severity and category posture." action={<LayoutDashboard className="panel-header-icon" size={22} />}>
            <div className="summary-grid tight-grid">
              {severityCards.map(({ severity, count, icon: Icon, label }) => (
                <div key={severity} className={`summary-card severity-${severity} micro-float`}>
                  <span className="card-icon"><Icon size={16} /></span>
                  <strong>{label}</strong>
                  <span>{count}</span>
                </div>
              ))}
            </div>
            <div className="category-stack">
              {categoryCards.map(({ category, count, icon: Icon, label, accent }) => (
                <div key={category} className={`category-card ${accent} micro-float`}>
                  <div className="category-card-title"><Icon size={16} /> {label}</div>
                  <strong>{count}</strong>
                </div>
              ))}
            </div>
          </Panel>

          <Panel className="span-4" title="Module progress" subtitle="Operational state by inspection stream." action={<Activity className="panel-header-icon" size={22} />}>
            <div className="status-grid stacked-grid">
              {categoryOrder.map((moduleName) => {
                const Icon = moduleMeta[moduleName].icon;
                return (
                  <div key={moduleName} className={`status-card state-${scan?.module_status[moduleName] ?? 'queued'} micro-float`}>
                    <span className="card-icon"><Icon size={16} /></span>
                    <strong>{moduleMeta[moduleName].label}</strong>
                    <span>{scan?.module_status[moduleName] ?? 'queued'}</span>
                  </div>
                );
              })}
            </div>
          </Panel>

          <Panel className="span-4" title="Analytics" subtitle="Category distribution and inspection intensity." action={<Gauge className="panel-header-icon" size={22} />}>
            <div id="analytics" className="analytics-grid">
              <div className="chart-card branded-card">
                <h3>Category mix</h3>
                <ResponsiveContainer width="100%" height={210}>
                  <PieChart>
                    <Pie data={categoryCards} dataKey="count" nameKey="label" innerRadius={45} outerRadius={78} paddingAngle={4}>
                      {categoryCards.map((entry) => (
                        <Cell key={entry.category} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ borderRadius: 14, border: '1px solid rgba(148,163,184,0.18)' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="chart-card branded-card">
                <h3>Live posture</h3>
                <p>{scan?.summary.total_findings ?? 0} findings tracked across runtime, static, security, and compliance streams.</p>
              </div>
            </div>
          </Panel>

          <Panel className="findings-panel span-4" title="Findings feed" subtitle="Evidence-first issue stream." action={<AlertTriangle className="panel-header-icon" size={22} />}>
            <div className="findings-list" id="findings">
              {filteredFindings.map((finding) => {
                const Icon = severityMeta[finding.severity].icon;
                return (
                  <button key={finding.id} className={`finding-card micro-float ${selectedFinding?.id === finding.id ? 'selected' : ''}`} onClick={() => setSelectedFindingId(finding.id)}>
                    <div className="finding-row">
                      <span className={`badge severity-${finding.severity}`}><Icon size={12} /> {finding.severity}</span>
                      <span className="badge neutral">{finding.category}</span>
                      <span className="badge neutral">{finding.verification}</span>
                    </div>
                    <strong>{finding.title}</strong>
                    <p>{finding.description_plain}</p>
                  </button>
                );
              })}
              {filteredFindings.length === 0 && <p>No findings yet. Start an inspection to populate results.</p>}
            </div>
          </Panel>

          <Panel className="detail-panel span-4" title="Finding detail" subtitle="Review evidence, decision, and fix path." action={<SearchCheck className="panel-header-icon" size={22} />}>
            {!selectedFinding && <p>Select a finding to review evidence.</p>}
            {selectedFinding && (
              <div className="stack">
                <div className="finding-row">
                  <span className={`badge severity-${selectedFinding.severity}`}>
                    {(() => {
                      const Icon = severityMeta[selectedFinding.severity].icon;
                      return <Icon size={12} />;
                    })()} {selectedFinding.severity}
                  </span>
                  <span className="badge neutral">{selectedFinding.review.decision}</span>
                  <span className="badge neutral">{selectedFinding.verification}</span>
                </div>
                <h3>{selectedFinding.title}</h3>
                <p>{selectedFinding.impact_plain}</p>
                <dl className="detail-grid">
                  <div>
                    <dt>Location</dt>
                    <dd>{selectedFinding.location.file ?? selectedFinding.location.url ?? 'Unknown'}</dd>
                  </div>
                  <div>
                    <dt>Lines / element</dt>
                    <dd>
                      {selectedFinding.location.line_start
                        ? `${selectedFinding.location.line_start}-${selectedFinding.location.line_end ?? selectedFinding.location.line_start}`
                        : selectedFinding.location.element ?? '—'}
                    </dd>
                  </div>
                  <div>
                    <dt>Source modules</dt>
                    <dd>{selectedFinding.source_modules.join(', ')}</dd>
                  </div>
                  <div>
                    <dt>CWE</dt>
                    <dd>{selectedFinding.cwe_id ?? '—'}</dd>
                  </div>
                </dl>
                <pre>{selectedFinding.evidence.snippet}</pre>
                <pre>{maskSecret(selectedFinding.evidence.captured_output)}</pre>

                <label>
                  Reviewer
                  <input value={reviewer} onChange={(event) => setReviewer(event.target.value)} />
                </label>
                <label>
                  Review reason
                  <textarea value={reviewReason} onChange={(event) => setReviewReason(event.target.value)} placeholder="Required for reject or escalate" />
                </label>
                <div className="button-row">
                  <button onClick={() => void updateReview('confirmed')}>Confirm</button>
                  <button onClick={() => void updateReview('rejected')}>Reject</button>
                  <button onClick={() => void updateReview('escalated')}>Escalate</button>
                </div>

                {selectedFinding.fix_suggestion && (
                  <>
                    <h3>Fix suggestion</h3>
                    <p>{selectedFinding.fix_suggestion.summary}</p>
                    {selectedFinding.fix_suggestion.diff && <pre>{selectedFinding.fix_suggestion.diff}</pre>}
                    <div className="button-row">
                      <button disabled={selectedFinding.review.decision !== 'confirmed'} onClick={() => void updateFixReview('approved')}>Approve fix</button>
                      <button onClick={() => void updateFixReview('declined')}>Decline fix</button>
                    </div>
                  </>
                )}
              </div>
            )}
          </Panel>

          <Panel className="export-panel span-12" title="Reports & exports" subtitle="Generate review-ready markdown summaries." action={<ArrowUpRight className="panel-header-icon" size={22} />}>
            <div id="reports" className="button-row">
              <button onClick={handleExport} disabled={!scanId}>Export markdown</button>
            </div>
            <pre>{exportMarkdown || 'Generate an export after a scan completes.'}</pre>
          </Panel>
        </main>
      </div>
    </div>
  );
}
