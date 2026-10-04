import type { ScanStatusResponse } from '../contracts/finding';

/** Saves text as a file named after the scanned host and start time, e.g. inspection-localhost-3000-2026-10-04-04-25.md */
export function downloadText(content: string, mimeType: string, scan: ScanStatusResponse, kind: string, extension: string) {
  let host = 'scan';
  try {
    host = new URL(scan.target_url).host.replace(/[^a-z0-9.-]+/gi, '-');
  } catch {
    // Keep the default name.
  }
  const stamp = new Date(scan.created_at).toISOString().slice(0, 16).replace(/[:T]/g, '-');
  const url = URL.createObjectURL(new Blob([content], { type: mimeType }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `${kind}-${host}-${stamp}.${extension}`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
