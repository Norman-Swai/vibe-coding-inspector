import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ReportPanel } from '../components/ReportPanel';
import { makeFinding, makeScan } from './utils';

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

describe('print report', () => {
  it('is hidden on screen and holds the scan header, every coverage row and every finding', () => {
    const { container } = render(<ReportPanel scan={SCAN} findings={FINDINGS} />);
    const report = container.querySelector<HTMLElement>('.print-report') as HTMLElement;
    expect(report).not.toBeVisible();
    const text = (element: HTMLElement) => element.textContent?.replace(/\s+/g, ' ').trim();

    expect(text(within(report).getByRole('heading', { level: 1, hidden: true }))).toBe('Inspection report — http://localhost:3000/');

    expect(within(report).getByText('scan-1')).toBeInTheDocument();
    expect(within(report).getByText('Authorised localhost')).toBeInTheDocument();
    expect(within(report).getByText('8 pages, 10 s request timeout')).toBeInTheDocument();
    expect(within(report).getByText('2 (Critical 0, High 1, Medium 1, Low 0, Info 0)')).toBeInTheDocument();

    const cells = (row: HTMLElement) => [...row.querySelectorAll('th, td')].map((cell) => text(cell as HTMLElement)).join(' ');
    const [header, ...rows] = within(report).getAllByRole('row', { hidden: true });
    expect(cells(header)).toBe('Module State Scanned Duration Notes');
    expect(rows.map(cells)).toEqual([
      'Runtime Done 3 URLs requested, 2 HTML pages inspected 1.5 s JavaScript is not executed',
      'Static code Failed — — Error: Repository path does not exist',
      'Security Done 1 page 12 ms —',
      'Compliance Skipped — — Public mode: no repository',
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
