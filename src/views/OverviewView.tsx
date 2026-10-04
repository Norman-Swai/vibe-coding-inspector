import { ArrowRight, BarChart3, Eye, ListChecks, Lock, Play, Rocket, ShieldCheck, SlidersHorizontal } from 'lucide-react';
import { ViewHeader } from '../components/ViewHeader';
import type { ScanStatusResponse } from '../contracts/finding';
import { hrefFor } from '../hooks/useHashRoute';
import { formatTime, MODULE_META, MODULES } from '../lib/meta';
import { useSettings } from '../lib/settings';

const STEPS = [
  {
    view: 'launch' as const,
    icon: Rocket,
    title: 'Launch',
    text: 'Enter the URL of an app you own or are authorised to test. Choose Localhost (can also read the source code) or Public site (passive, read-only), confirm authorisation and start.',
  },
  {
    view: 'launch' as const,
    icon: Play,
    title: 'Watch it scan',
    text: 'Four modules run in parallel. The Launch view and the bar at the top show live progress and the step currently running.',
  },
  {
    view: 'analytics' as const,
    icon: BarChart3,
    title: 'See what was done',
    text: 'Analytics lists every HTTP request, every check with its result and every command with its output, plus what each module covered, skipped or failed on.',
  },
  {
    view: 'findings' as const,
    icon: ListChecks,
    title: 'Review findings',
    text: 'Each observation comes with its artifacts: source lines, response headers or page elements. Confirm, reject or escalate it, approve fixes, and export a report.',
  },
];

export function OverviewView({ scan, findingsCount }: { scan: ScanStatusResponse | null; findingsCount: number }) {
  const { open } = useSettings();
  return (
    <>
      <ViewHeader
        title="Inspect a web app before you ship it"
        description="Vibe Coding Inspector crawls a running site — and, if you point it at the code, reads the repository — to find broken pages, security gaps, accessibility and compliance problems. Every finding comes with the evidence it is based on, and nothing on your site is changed."
        actions={
          <a className="button button-primary" href={hrefFor('launch')}>
            Start a scan <ArrowRight size={16} aria-hidden="true" />
          </a>
        }
      />

      {scan && (
        <p className="notice current-scan" data-tone={scan.status === 'running' ? 'warning' : 'neutral'}>
          {scan.status === 'running' ? (
            <>
              <span className="spinner" aria-hidden="true" /> Scanning <span className="break-anywhere">{scan.target_url}</span> now.{' '}
              <a href={hrefFor('launch')}>Watch progress</a>
            </>
          ) : (
            <>
              Last scan: <span className="break-anywhere">{scan.target_url}</span>, {formatTime(scan.finished_at)}, {findingsCount} finding{findingsCount === 1 ? '' : 's'}.{' '}
              <a href={hrefFor('findings')}>Review findings</a> · <a href={hrefFor('analytics')}>See what was done</a>
            </>
          )}
        </p>
      )}

      <section className="panel" aria-labelledby="how-title">
        <h2 id="how-title">How it works</h2>
        <ol className="steps" role="list">
          {STEPS.map(({ view, icon: Icon, title, text }, index) => (
            <li key={title} className="step">
              <span className="step-number" aria-hidden="true">
                {index + 1}
              </span>
              <div>
                <h3>
                  <Icon size={18} aria-hidden="true" /> <a href={hrefFor(view)}>{title}</a>
                </h3>
                <p className="muted">{text}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="panel" aria-labelledby="checks-title">
        <h2 id="checks-title">What gets checked</h2>
        <div className="card-grid">
          {MODULES.map((module) => {
            const { icon: Icon, label, summary, checks } = MODULE_META[module];
            return (
              <article key={module} className="info-card">
                <h3>
                  <span className="module-icon">
                    <Icon size={18} aria-hidden="true" />
                  </span>
                  {label}
                </h3>
                <p className="muted small">{summary}</p>
                <ul>
                  {checks.map((check) => (
                    <li key={check}>{check}</li>
                  ))}
                </ul>
              </article>
            );
          })}
        </div>
      </section>

      <section className="panel" aria-labelledby="safety-title">
        <h2 id="safety-title">Modes and safety</h2>
        <div className="card-grid two">
          <article className="info-card">
            <h3>
              <Lock size={18} aria-hidden="true" /> Localhost mode
            </h3>
            <p className="muted small">For apps you are developing.</p>
            <ul>
              <li>Only accepts localhost, 127.0.0.1 or [::1]</li>
              <li>Can also read a local repository: static analysis, secret scanning, npm audit</li>
            </ul>
          </article>
          <article className="info-card">
            <h3>
              <Eye size={18} aria-hidden="true" /> Public site mode
            </h3>
            <p className="muted small">For deployed sites you are authorised to check.</p>
            <ul>
              <li>Passive GET requests only, within the page limit you set</li>
              <li>Respects robots.txt; never reads source code</li>
            </ul>
          </article>
        </div>
        <ul className="safety-list">
          <li>
            <ShieldCheck size={16} aria-hidden="true" /> You must confirm you own the app or are authorised to test it.
          </li>
          <li>
            <ShieldCheck size={16} aria-hidden="true" /> Read-only: no forms are submitted and nothing is changed. Suggested fixes are never applied automatically.
          </li>
          <li>
            <ShieldCheck size={16} aria-hidden="true" /> Secrets found in code are masked on screen and in reports.
          </li>
          <li>
            <ShieldCheck size={16} aria-hidden="true" /> JavaScript is not executed, so client-rendered content and console errors are not inspected.
          </li>
        </ul>
        <p className="muted small">
          <SlidersHorizontal size={14} aria-hidden="true" /> Theme, density, reviewer name and scan limits are in the{' '}
          <button type="button" className="link-button" onClick={() => open()}>
            Settings panel
          </button>
          .
        </p>
      </section>
    </>
  );
}
