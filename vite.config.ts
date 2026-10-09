/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    // Claude Code keeps throwaway checkouts under .claude/worktrees; their copies of the tests must not run here.
    exclude: ['**/node_modules/**', '**/dist/**', '**/.claude/**'],
  },
});
