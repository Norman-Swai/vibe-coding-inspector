import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App from '../App';
import { DEFAULT_SETTINGS, loadSettings, sanitizeSettings, SETTINGS_KEY } from '../lib/settings';
import { installMatchMedia } from './utils';

describe('settings model', () => {
  it('clamps numbers and rejects unknown values', () => {
    expect(sanitizeSettings({ theme: 'neon', density: 'compact', maxPages: 500, timeoutSeconds: '0', reviewer: 42 })).toEqual({
      ...DEFAULT_SETTINGS,
      density: 'compact',
      maxPages: 50,
      timeoutSeconds: 1,
    });
  });

  it('falls back to defaults when storage is unavailable or corrupt', () => {
    window.localStorage.setItem(SETTINGS_KEY, '{not json');
    expect(loadSettings()).toEqual(DEFAULT_SETTINGS);
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    expect(loadSettings()).toEqual(DEFAULT_SETTINGS);
  });
});

describe('settings drawer', () => {
  async function openSettings() {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: 'Settings' }));
    return { user, dialog: screen.getByRole('dialog', { name: 'Settings' }) };
  }

  it('applies appearance immediately and persists it', async () => {
    const { user, dialog } = await openSettings();
    const root = document.documentElement;
    expect(root.dataset.theme).toBe('light');

    await user.click(within(dialog).getByRole('radio', { name: 'Dark' }));
    await user.click(within(dialog).getByRole('radio', { name: 'Compact' }));
    await user.click(within(dialog).getByRole('radio', { name: 'Reduce' }));

    expect(root.dataset).toMatchObject({ theme: 'dark', density: 'compact', motion: 'reduced' });
    expect(JSON.parse(window.localStorage.getItem(SETTINGS_KEY)!)).toMatchObject({ theme: 'dark', density: 'compact', motion: 'reduced' });
  });

  it('follows the operating system theme when set to System', async () => {
    installMatchMedia((query) => query === '(prefers-color-scheme: dark)');
    render(<App />);
    expect(document.documentElement.dataset.theme).toBe('dark');
  });

  it('feeds scan limits into the launch form and does not duplicate the controls there', async () => {
    window.location.hash = '#/launch';
    const { user, dialog } = await openSettings();
    const maxPages = within(dialog).getByLabelText('Max pages to crawl');
    await user.clear(maxPages);
    expect(within(dialog).getByText('Enter a whole number from 1 to 50.')).toBeInTheDocument();
    await user.type(maxPages, '20');
    await user.keyboard('{Escape}');

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByText(/Limits: 20 pages · 10 s timeout/)).toBeInTheDocument();
    // Each setting has exactly one control, and it lives in the drawer.
    expect(screen.queryByLabelText('Max pages to crawl')).not.toBeInTheDocument();
    expect(screen.queryByRole('group', { name: 'Theme' })).not.toBeInTheDocument();
  });

  it('opens with focus on the checked theme option, so Space changes nothing', async () => {
    window.localStorage.setItem(SETTINGS_KEY, JSON.stringify({ theme: 'dark' }));
    const { user, dialog } = await openSettings();
    expect(within(dialog).getByRole('radio', { name: 'Dark' })).toHaveFocus();
    await user.keyboard(' ');
    expect(JSON.parse(window.localStorage.getItem(SETTINGS_KEY)!)).toMatchObject({ theme: 'dark' });
  });

  it('exposes no page landmarks of its own', async () => {
    const { dialog } = await openSettings();
    expect(within(dialog).queryByRole('banner')).not.toBeInTheDocument();
    expect(within(dialog).queryByRole('contentinfo')).not.toBeInTheDocument();
    expect(dialog.querySelector('header, footer')).toBeNull();
    expect(within(dialog).getByRole('heading', { level: 2, name: 'Settings' })).toBeInTheDocument();
  });

  it('returns focus to the settings button when closed', async () => {
    const { user } = await openSettings();
    await user.click(screen.getByRole('button', { name: 'Done' }));
    expect(screen.getByRole('button', { name: 'Settings' })).toHaveFocus();
  });

  it('resets everything to defaults', async () => {
    const { user, dialog } = await openSettings();
    await user.click(within(dialog).getByRole('radio', { name: 'Dark' }));
    await user.type(within(dialog).getByLabelText('Reviewer name'), 'Norman');
    await user.click(within(dialog).getByRole('button', { name: /Reset to defaults/ }));
    expect(within(dialog).getByRole('radio', { name: 'System' })).toBeChecked();
    expect(within(dialog).getByLabelText('Reviewer name')).toHaveValue('');
  });
});
