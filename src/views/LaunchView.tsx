import { type LaunchDraft, LaunchPanel } from '../components/LaunchPanel';
import { ScanMonitor } from '../components/ScanMonitor';
import { ViewHeader } from '../components/ViewHeader';
import type { ScanRequest, ScanStatusResponse } from '../contracts/finding';

export function LaunchView({
  draft,
  onDraftChange,
  scan,
  error,
  findingsCount,
  starting,
  startError,
  localStart,
  blockedReason,
  onStart,
}: {
  draft: LaunchDraft;
  onDraftChange: (patch: Partial<LaunchDraft>) => void;
  scan: ScanStatusResponse | null;
  error: string | null;
  findingsCount: number;
  starting: boolean;
  startError: string | null;
  localStart: number | null;
  blockedReason: string | null;
  onStart: (request: ScanRequest) => void;
}) {
  return (
    <>
      <ViewHeader
        title="Launch a scan"
        description="Enter the address of an app you own or are authorised to test. Scans are read-only; progress appears in Scan status as each module works."
      />
      <div className="launch-grid">
        <LaunchPanel draft={draft} onDraftChange={onDraftChange} busy={starting} running={scan?.status === 'running'} blockedReason={blockedReason} error={startError} onStart={onStart} />
        <ScanMonitor scan={scan} error={error} findingsCount={findingsCount} localStart={localStart} />
      </div>
    </>
  );
}
