import { readFileSync } from 'node:fs';
import postcss, { type AtRule, type Rule } from 'postcss';
import { describe, expect, it } from 'vitest';

// jsdom does not lay out or paint, so these check the stylesheet itself: the rules behind the touch, phone and
// print layouts, and the badge colour maths (color-mix in sRGB is a straight blend of the channel values).
// Read from disk: the vitest config turns every .css import, ?raw included, into an empty module.
const root = postcss.parse(readFileSync((expect.getState().testPath ?? '').replace(/test\/styles\.test\.ts$/, 'styles.css'), 'utf8'));

function mediaOf(rule: Rule) {
  const parent = rule.parent;
  return parent?.type === 'atrule' && (parent as AtRule).name === 'media' ? (parent as AtRule).params : null;
}

/** Declarations of every rule whose selector list contains `selector`, inside the given @media (or none). Later wins. */
function declarations(selector: string, media: string | null = null) {
  const found: Record<string, string> = {};
  root.walkRules((rule) => {
    if (!rule.selectors.includes(selector) || mediaOf(rule) !== media) return;
    rule.walkDecls((decl) => {
      found[decl.prop] = decl.important ? `${decl.value} !important` : decl.value;
    });
  });
  return found;
}

type Rgb = [number, number, number];
const hex = (value: string): Rgb => [1, 3, 5].map((index) => parseInt(value.slice(index, index + 2), 16)) as Rgb;
/** color-mix(in srgb, a weight%, b): a weighted blend of sRGB channels. */
const mix = (a: Rgb, b: Rgb, weight: number): Rgb => a.map((channel, index) => channel * weight + b[index] * (1 - weight)) as Rgb;
const percent = (value: string) => Number(/(\d+(?:\.\d+)?)%/.exec(value)?.[1]) / 100;

function luminance([r, g, b]: Rgb) {
  const linear = (channel: number) => {
    const c = channel / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b);
}

function contrast(a: Rgb, b: Rgb) {
  const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (high + 0.05) / (low + 0.05);
}

describe('badge contrast', () => {
  const badge = declarations('.badge');
  const textWeight = percent(badge.color);
  const tintWeight = percent(badge.background);
  const rowWeight = percent(declarations(".finding-item[aria-current='true']").background);
  const tones = ['sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-info', 'success', 'warning', 'danger', 'muted'];

  it.each([
    ['light', declarations(':root')],
    ['dark', declarations(":root[data-theme='dark']")],
  ])('reaches 4.5:1 in the %s theme on the panel, the page and the selected finding row', (_theme, tokens) => {
    const text = hex(tokens['--text']);
    const surface = hex(tokens['--surface']);
    const backgrounds = { panel: surface, page: hex(tokens['--bg']), selectedRow: mix(hex(tokens['--accent']), surface, rowWeight) };
    const ratios: Record<string, number> = {};
    for (const tone of tones) {
      const colour = hex(tokens[`--${tone}`]);
      for (const [name, background] of Object.entries(backgrounds)) {
        ratios[`${tone} on ${name}`] = contrast(mix(colour, text, textWeight), mix(colour, background, tintWeight));
      }
    }
    for (const [name, ratio] of Object.entries(ratios)) expect(ratio, name).toBeGreaterThanOrEqual(4.5);
  });
});

describe('touch screens', () => {
  const coarse = '(pointer: coarse)';

  it('give every text-sized control a 44px tap target', () => {
    expect(declarations('.segmented-option span', coarse)['min-height']).toBe('var(--control-h)');
    for (const selector of ['.link-button', 'a.badge', '.scan-chip', '.brand', '.viewnav a', '.module-notes summary', '.activity-output summary']) {
      expect(declarations(selector, coarse)['min-height'], selector).toBe('2.75rem');
    }
  });

  it('keep the taller phone tabs: the touch rule precedes the phone block', () => {
    const order: string[] = [];
    root.walkRules((rule) => {
      if (rule.selectors.includes('.viewnav a') && mediaOf(rule)) order.push(mediaOf(rule) as string);
    });
    expect(order).toEqual([coarse, '(max-width: 719px)']);
  });
});

describe('phones', () => {
  const phone = '(max-width: 719px)';

  it('scroll focused elements clear of the fixed tab bar', () => {
    expect(declarations('html', phone)['scroll-padding-bottom']).toContain('3.75rem');
  });

  it('draw the active tab indicator as a straight bar beside, not under, the findings count', () => {
    expect(declarations(".viewnav a[aria-current='page']", phone)['box-shadow']).toBe('none');
    expect(declarations(".viewnav a[aria-current='page']::before", phone)).toMatchObject({ height: '2px', top: '0' });
    expect(declarations('.nav-count', phone).left).toBe('calc(50% + 0.75rem)');
  });

  it('wrap the current scan step instead of cutting it off', () => {
    expect(declarations('.monitor-now-text', phone)['white-space']).toBe('normal');
  });
});

describe('settings drawer', () => {
  it('bounds its column to the drawer and wraps the footer buttons', () => {
    expect(declarations('.drawer')['grid-template-columns']).toBe('minmax(0, 1fr)');
    expect(declarations('.drawer-footer')['flex-wrap']).toBe('wrap');
  });
});

describe('headings', () => {
  it('are never upper-cased through CSS, which Chrome copies into accessible names', () => {
    const uppercased: string[] = [];
    root.walkDecls('text-transform', (decl) => {
      if (decl.value === 'uppercase') uppercased.push((decl.parent as Rule).selector);
    });
    expect(uppercased).toEqual([]);
  });
});

describe('print', () => {
  it('shows only the formatted report', () => {
    const hidden = declarations('.report-panel > :not(.print-report)', 'print');
    expect(hidden.display).toBe('none !important');
    expect(declarations('.print-report[hidden]', 'print').display).toBe('block');
    expect(declarations('.print-excerpt', 'print')['font-family']).toBe('var(--font-mono)');
  });
});
