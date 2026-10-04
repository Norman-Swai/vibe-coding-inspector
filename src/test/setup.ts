import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach, vi } from 'vitest';
import { installMatchMedia } from './utils';

// jsdom does not implement layout APIs.
Element.prototype.scrollIntoView ??= function scrollIntoView() {};

beforeEach(() => {
  installMatchMedia();
  window.localStorage.clear();
  window.sessionStorage.clear();
  window.history.replaceState(null, '', '/');
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  const root = document.documentElement;
  delete root.dataset.theme;
  delete root.dataset.density;
  delete root.dataset.motion;
});
