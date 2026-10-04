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
    snippet: Optional[str] = None
    captured_output: Optional[str] = None


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


class ScanRequest(BaseModel):
    target_url: str
    repo_path: Optional[str] = None
    authorization_confirmed: bool
    inspection_mode: InspectionMode = InspectionMode.localhost


class ScanRecord(BaseModel):
    id: str
    target_url: str
    repo_path: Optional[str] = None
    inspection_mode: InspectionMode
    created_at: str
    module_status: Dict[ModuleName, ModuleState]
    findings: List[Finding] = Field(default_factory=list)
    errors: Dict[ModuleName, str] = Field(default_factory=dict)


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
    created_at: str
    module_status: Dict[ModuleName, ModuleState]
    summary: ScanSummary
