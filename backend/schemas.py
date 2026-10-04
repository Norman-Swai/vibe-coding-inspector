from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = 'critical'
    high = 'high'
    medium = 'medium'
    low = 'low'
    info = 'info'


SEVERITY_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]


class Verification(str, Enum):
    confirmed = 'confirmed'
    hypothesis = 'hypothesis'


class ModuleName(str, Enum):
    runtime = 'runtime'
    static = 'static'
    security = 'security'
    compliance = 'compliance'


class ModuleState(str, Enum):
    queued = 'queued'
    running = 'running'
    done = 'done'
    failed = 'failed'
    skipped = 'skipped'


TERMINAL_MODULE_STATES = {ModuleState.done, ModuleState.failed, ModuleState.skipped}


class ScanState(str, Enum):
    running = 'running'
    completed = 'completed'


class ReviewDecision(str, Enum):
    pending = 'pending'
    confirmed = 'confirmed'
    rejected = 'rejected'
    escalated = 'escalated'


class FixReviewDecision(str, Enum):
    pending = 'pending'
    approved = 'approved'
    declined = 'declined'


class InspectionMode(str, Enum):
    localhost = 'localhost'
    public_readonly = 'public-readonly'


class Location(BaseModel):
    file: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    url: Optional[str] = None
    element: Optional[str] = None


class Evidence(BaseModel):
    # The exact excerpt that was observed (numbered source lines, HTML elements, header lines). Secrets are masked.
    snippet: Optional[str] = None
    # Where the excerpt came from, e.g. "GET http://localhost:3000/ -> 200 text/html (35 ms)".
    captured_output: Optional[str] = None
    # The rule that was evaluated, in plain words, so a reviewer can reproduce the result.
    check: Optional[str] = None
    occurrences: int = 1


class FixSuggestion(BaseModel):
    summary: str
    diff: Optional[str] = None


class ReviewState(BaseModel):
    decision: ReviewDecision = ReviewDecision.pending
    reason: Optional[str] = None
    reviewer: Optional[str] = None
    timestamp: Optional[str] = None


class FixReviewState(BaseModel):
    decision: FixReviewDecision = FixReviewDecision.pending
    reviewer: Optional[str] = None
    timestamp: Optional[str] = None


class Finding(BaseModel):
    id: str
    title: str
    category: ModuleName
    severity: Severity
    verification: Verification
    source_modules: List[ModuleName]
    location: Location
    evidence: Evidence
    description_plain: str
    impact_plain: str
    cwe_id: Optional[str] = None
    fix_suggestion: Optional[FixSuggestion] = None
    review: ReviewState = Field(default_factory=ReviewState)
    fix_review: Optional[FixReviewState] = Field(default_factory=FixReviewState)


class ScanOptions(BaseModel):
    max_pages: int = Field(8, ge=1, le=50, description='Maximum number of same-origin URLs requested by the crawler.')
    timeout_seconds: float = Field(10, ge=1, le=60, description='Per-request timeout.')


class ScanRequest(ScanOptions):
    target_url: str
    repo_path: Optional[str] = None
    authorization_confirmed: bool
    inspection_mode: InspectionMode = InspectionMode.localhost


class ModuleReport(BaseModel):
    state: ModuleState = ModuleState.queued
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None
    scanned: int = 0
    scanned_label: str = ''
    notes: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class ScanRecord(BaseModel):
    id: str
    target_url: str
    repo_path: Optional[str] = None
    inspection_mode: InspectionMode
    options: ScanOptions = Field(default_factory=ScanOptions)
    status: ScanState = ScanState.running
    created_at: str
    finished_at: Optional[str] = None
    modules: Dict[ModuleName, ModuleReport]
    findings: List[Finding] = Field(default_factory=list)


class ScanStartResponse(BaseModel):
    scan_id: str


class ScanSummary(BaseModel):
    total_findings: int
    by_severity: Dict[Severity, int]
    by_category: Dict[ModuleName, int]


class ScanStatusResponse(BaseModel):
    id: str
    target_url: str
    repo_path: Optional[str]
    inspection_mode: InspectionMode
    options: ScanOptions
    status: ScanState
    created_at: str
    finished_at: Optional[str] = None
    # Kept for clients of the original contract; mirrors modules[name].state.
    module_status: Dict[ModuleName, ModuleState]
    modules: Dict[ModuleName, ModuleReport]
    summary: ScanSummary
