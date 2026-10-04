export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Verification = 'confirmed' | 'hypothesis';
export type ModuleName = 'runtime' | 'static' | 'security' | 'compliance';
export type ModuleState = 'queued' | 'running' | 'done' | 'failed' | 'skipped';
export type ReviewDecision = 'pending' | 'confirmed' | 'rejected' | 'escalated';
export type FixReviewDecision = 'pending' | 'approved' | 'declined';

export interface FileLocation {
  file?: string;
  line_start?: number;
  line_end?: number;
  url?: string;
  element?: string;
}

export interface Evidence {
  snippet?: string;
  captured_output?: string;
}

export interface ReviewState {
  decision: ReviewDecision;
  reason?: string;
  reviewer?: string;
  timestamp?: string;
}

export interface FixReviewState {
  decision: FixReviewDecision;
  reviewer?: string;
  timestamp?: string;
}

export interface FixSuggestion {
  summary: string;
  diff?: string;
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
  cwe_id?: string;
  fix_suggestion?: FixSuggestion;
  review: ReviewState;
  fix_review?: FixReviewState;
}

export interface ScanRequest {
  target_url: string;
  repo_path?: string;
  authorization_confirmed: boolean;
  inspection_mode: 'localhost' | 'public-readonly';
}

export interface ScanStatusResponse {
  id: string;
  target_url: string;
  repo_path?: string;
  inspection_mode: 'localhost' | 'public-readonly';
  created_at: string;
  module_status: Record<ModuleName, ModuleState>;
  summary: {
    total_findings: number;
    by_severity: Record<Severity, number>;
    by_category: Record<ModuleName, number>;
  };
}
