import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ReportPanel } from '../components/ReportPanel';
import { makeEvent, makeFinding, makeScan } from './utils';

const FINDINGS = [
  makeFinding({ id: 'a', title: 'Form controls have no accessible label', severity: 'medium' }),
  makeFinding({
    id: 'b',
    title: 'Hard-coded API key',
    severity: 'high',
    category: 'security',
    source_modules: ['security'],
    verification: 'hypothesis',
    location: { file: 'src/config.js', line_start: 4 },
    evidence: { snippet: 'const key = "AKIA••••••"', captured_output: 'src/config.js scanned for secret-shaped literals', check: 'Secret-shaped literals.', occurrences: 2 },
    description_plain: 'A credential is committed to the repository.',
    impact_plain: 'Anyone with the source can use it.',
    cwe_id: 'CWE-798',
    fix_suggestion: { summary: 'Move it to an environment variable.', diff: '-const key = "..."\n+const key = process.env.KEY' },
    review: { decision: 'rejected', reason: 'Test fixture only', reviewer: 'Norman', timestamp: '2026-10-04T05:00:00+00:00' },
    fix_review: { decision: 'declined', reviewer: 'Norman' },
  }),
];

const SCAN = makeScan({
  modules: {
    ...makeScan().modules,
    runtime: { state: 'done', scanned: 3, scanned_label: '3 URLs requested, 2 HTML pages inspected', notes: ['JavaScript is not executed'], duration_ms: 1500 },
    static: { state: 'failed', scanned: 0, scanned_label: '', notes: [], error: 'Repository path does not exist' },
    compliance: { state: 'skipped', scanned: 0, scanned_label: '', notes: ['Public mode: no repository'] },
  },
});

const ACTIVITY = [
  makeEvent({ seq: 1, message: 'Scan started: http://localhost:3000/ (localhost mode)' }),
  makeEvent({ seq: 2, kind: 'request', message: 'GET http://localhost:3000/ -> 200 OK text/html (5 ms)', request: { method: 'GET', url: 'http://localhost:3000/', status: 200 } }),
  makeEvent({ seq: 3, kind: 'request', message: 'GET http://localhost:3000/docs -> 404 Not Found (2 ms)', request: { method: 'GET', url: 'http://localhost:3000/docs', status: 404 } }),
  makeEvent({ seq: 4, module: 'runtime', kind: 'check', message: 'Inspected http://localhost:3000/: 1 issue' }),
  makeEvent({ seq: 5, module: 'security', kind: 'check', message: 'Response headers of http://localhost:3000/: 3 issues' }),
  makeEvent({ seq: 6, module: 'security', kind: 'command', message: '$ npm audit --json → exit 0, 0 vulnerable packages', output: 'vulnerabilities: {"total": 0}\ntoken=AKIA' + 'QWERTYUIOPASDFGH' }),
];

describe('print report', () => {
  it('is hidden on screen and holds the scan header, every coverage row, what was done and every finding', () => {
    const { container } = render(<ReportPanel scan={SCAN} findings={FINDINGS} activity={ACTIVITY} activityDropped={3} />);
    const report = container.querySelector<HTMLElement>('.print-report') as HTMLElement;
    expect(report).not.toBeVisible();
    const text = (element: HTMLElement) => element.textContent?.replace(/\s+/g, ' ').trim();

    expect(text(within(report).getByRole('heading', { level: 1, hidden: true }))).toBe('Inspection report — http://localhost:3000/');

    expect(within(report).getByText('scan-1')).toBeInTheDocument();
    expect(within(report).getByText('Authorised localhost')).toBeInTheDocument();
    expect(within(report).getByText('8 pages, 10 s request timeout')).toBeInTheDocument();
    expect(within(report).getByText('2 (Critical 0, High 1, Medium 1, Low 0, Info 0)')).toBeInTheDocument();

    const cells = (row: HTMLElement) => [...row.querySelectorAll('th, td')].map((cell) => text(cell as HTMLElement)).join(' ');
    const [coverage, done] = within(report).getAllByRole('table', { hidden: true });
    const [header, ...rows] = within(coverage).getAllByRole('row', { hidden: true });
    expect(cells(header)).toBe('Module State Scanned Duration Notes');
    expect(rows.map(cells)).toEqual([
      'Runtime Done 3 URLs requested, 2 HTML pages inspected 1.5 s JavaScript is not executed',
      'Static code Failed — — Error: Repository path does not exist',
      'Security Done 1 page 12 ms —',
      'Compliance Skipped — — Public mode: no repository',
    ]);

    // What was done: the same counts, commands (output included, secrets masked) and checks as the Markdown report.
    const whatWasDone = within(report).getByRole('heading', { level: 2, name: 'What was done', hidden: true });
    const summary = whatWasDone.nextElementSibling as HTMLElement;
    expect(within(summary).getAllByRole('term', { hidden: true }).map((term) => `${text(term)}: ${text(term.nextElementSibling as HTMLElement)}`)).toEqual([
      'HTTP requests sent: 2',
      'Checks evaluated: 2',
      'Commands run: 1',
      'Not recorded: 3 activity events (cap reached)',
    ]);
    const command = report.querySelector('.print-command') as HTMLElement;
    expect(text(command.querySelector('strong') as HTMLElement)).toBe('$ npm audit --json → exit 0, 0 vulnerable packages');
    expect(command.querySelector('pre')?.textContent).toContain('vulnerabilities: {"total": 0}');
    expect(command.querySelector('pre')?.textContent).not.toContain('QWERTYUIOP');
    expect(within(done).getAllByRole('row', { hidden: true }).map(cells)).toEqual([
      'Module Check',
      'Runtime Inspected http://localhost:3000/: 1 issue',
      'Security Response headers of http://localhost:3000/: 3 issues',
    ]);

    // Most severe first, numbered, with every artifact and decision a reviewer would want on paper.
    const findings = within(report).getAllByRole('article', { hidden: true });
    const facts = (article: HTMLElement) => within(article).getAllByRole('term', { hidden: true }).map((term) => `${text(term)}: ${text(term.nextElementSibling as HTMLElement)}`);
    const blocks = (article: HTMLElement) => [...article.querySelectorAll('p, pre')].map((node) => text(node as HTMLElement));
    expect(findings.map((article) => text(within(article).getByRole('heading', { level: 3, hidden: true })))).toEqual([
      '1. Hard-coded API key',
      '2. Form controls have no accessible label',
    ]);
    expect(facts(findings[0])).toEqual([
      'Severity: High',
      'Verification: Hypothesis — a person must confirm it',
      'Module: Security',
      'Category: Security',
      'Location: src/config.js:4',
      'Check: Secret-shaped literals.',
      'Source: src/config.js scanned for secret-shaped literals',
      'Occurrences: 2',
      'CWE: CWE-798',
      expect.stringMatching(/^Review: Rejected by Norman, .+ — “Test fixture only”$/),
      'Fix decision: Declined by Norman',
    ]);
    expect(blocks(findings[0])).toEqual([
      'const key = "AKIA••••••"',
      'A credential is committed to the repository.',
      'Impact: Anyone with the source can use it.',
      'Suggested fix: Move it to an environment variable.',
      '-const key = "..." +const key = process.env.KEY',
    ]);
    expect(findings[0].querySelectorAll('pre.print-excerpt')).toHaveLength(2);
    expect(facts(findings[1])).toEqual([
      'Severity: Medium',
      'Verification: Observed directly',
      'Module: Runtime',
      'Category: Runtime',
      'Location: / · line 11',
      'Element: <input name="phone">',
      'Check: Each control needs a label.',
      'Source: GET http://localhost:3000/ -> 200 OK text/html (5 ms)',
      'Review: Pending',
      'Fix decision: Pending',
    ]);
    expect(blocks(findings[1])).toEqual([
      '/ L11: <input name="phone">',
      'Some form fields have no programmatic label.',
      'Impact: Screen-reader users cannot tell what to enter.',
      'Suggested fix: Add a label.',
    ]);
  });

  it('prints straight away without loading the Markdown report, which stays a preview on demand', async () => {
    const print = vi.spyOn(window, 'print').mockImplementation(() => undefined);
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<ReportPanel scan={SCAN} findings={FINDINGS} />);

    await user.click(screen.getByRole('button', { name: 'Print / PDF' }));
    expect(print).toHaveBeenCalledTimes(1);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.queryByLabelText('Markdown report preview')).not.toBeInTheDocument();
  });

  it('is absent without a scan', () => {
    const { container } = render(<ReportPanel scan={null} findings={[]} />);
    expect(container.querySelector('.print-report')).toBeNull();
    expect(screen.getByRole('button', { name: 'Print / PDF' })).toBeDisabled();
  });
});
