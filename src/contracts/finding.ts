// Mirrors backend/schemas.py. Keep the two in sync.
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Verification = 'confirmed' | 'hypothesis';
export type ModuleName = 'runtime' | 'static' | 'security' | 'compliance';
export type ModuleState = 'queued' | 'running' | 'done' | 'failed' | 'skipped';
export type ScanState = 'running' | 'completed';
export type ReviewDecision = 'pending' | 'confirmed' | 'rejected' | 'escalated';
export type FixReviewDecision = 'pending' | 'approved' | 'declined';
export type InspectionMode = 'localhost' | 'public-readonly';

export interface FileLocation {
  file?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  url?: string | null;
  element?: string | null;
}

export interface Evidence {
  /** Exact excerpt that was observed; secrets are masked by the backend. */
  snippet?: string | null;
  /** Where the excerpt came from, e.g. the request that produced it. */
  captured_output?: string | null;
  /** The rule that was evaluated, in plain words. */
  check?: string | null;
  occurrences: number;
}

export interface ReviewState {
  decision: ReviewDecision;
  reason?: string | null;
  reviewer?: string | null;
  timestamp?: string | null;
}

export interface FixReviewState {
  decision: FixReviewDecision;
  reviewer?: string | null;
  timestamp?: string | null;
}

export interface FixSuggestion {
  summary: string;
  diff?: string | null;
}

export interface Finding {
  id: string;
  title: string;
  category: ModuleName;
  severity: Severity;
  verification: Verification;
  source_modules: ModuleName[];
  location: FileLocation;
  evidence: Evidence;
  description_plain: string;
  impact_plain: string;
  cwe_id?: string | null;
  fix_suggestion?: FixSuggestion | null;
  review: ReviewState;
  fix_review?: FixReviewState | null;
}

export interface ScanOptions {
  max_pages: number;
  timeout_seconds: number;
}

export interface ScanRequest extends ScanOptions {
  target_url: string;
  repo_path?: string;
  authorization_confirmed: boolean;
  inspection_mode: InspectionMode;
}

export interface ModuleReport {
  state: ModuleState;
  started_at?: string | null;
  finished_at?: string | null;
  duration_ms?: number | null;
  scanned: number;
  scanned_label: string;
  notes: string[];
  error?: string | null;
}

export interface ScanStatusResponse {
  id: string;
  target_url: string;
  repo_path?: string | null;
  inspection_mode: InspectionMode;
  options: ScanOptions;
  status: ScanState;
  created_at: string;
  finished_at?: string | null;
  module_status: Record<ModuleName, ModuleState>;
  modules: Record<ModuleName, ModuleReport>;
  summary: {
    total_findings: number;
    by_severity: Record<Severity, number>;
    by_category: Record<ModuleName, number>;
  };
  activity_count: number;
  last_activity?: string | null;
}

export type ActivityKind = 'step' | 'request' | 'check' | 'command' | 'result' | 'warning' | 'error';

export interface RequestInfo {
  method: string;
  url: string;
  final_url?: string | null;
  status?: number | null;
  content_type?: string | null;
  bytes?: number | null;
  duration_ms?: number | null;
  error?: string | null;
}

/** One thing the inspector did during a scan. module is null for shared work (HTTP client, crawler, repo index). */
export interface ActivityEvent {
  seq: number;
  at_ms: number;
  module: ModuleName | null;
  kind: ActivityKind;
  message: string;
  output?: string | null;
  request?: RequestInfo | null;
}

export interface ActivityPage {
  events: ActivityEvent[];
  next_seq: number;
  dropped: number;
}
