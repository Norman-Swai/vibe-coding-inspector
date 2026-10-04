from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .orchestrator import orchestrator, store
from .schemas import (
    FixReviewState,
    Finding,
    InspectionMode,
    ModuleName,
    ReviewState,
    ScanRequest,
    ScanStartResponse,
    ScanStatusResponse,
)


app = FastAPI(title='Vibe Coding Inspector', version='0.1.0')
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


def _validate_request(payload: ScanRequest) -> None:
    parsed = urlparse(payload.target_url)
    if parsed.scheme not in {'http', 'https'}:
        raise HTTPException(status_code=400, detail='Only http and https targets are allowed.')
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=400, detail='Authorization confirmation is required.')
    if payload.inspection_mode == InspectionMode.localhost and parsed.hostname not in {'localhost', '127.0.0.1', '::1'}:
        raise HTTPException(status_code=400, detail='Localhost mode only accepts localhost, 127.0.0.1, or ::1.')
    if payload.repo_path and not Path(payload.repo_path).is_absolute():
        raise HTTPException(status_code=400, detail='Repository path must be absolute.')


@app.post('/api/scans', response_model=ScanStartResponse)
def start_scan(payload: ScanRequest) -> ScanStartResponse:
    _validate_request(payload)
    record = orchestrator.start_scan(payload)
    return ScanStartResponse(scan_id=record.id)


@app.get('/api/scans/{scan_id}', response_model=ScanStatusResponse)
def get_scan(scan_id: str) -> ScanStatusResponse:
    try:
        return orchestrator.get_status(scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail='Scan not found') from exc


@app.get('/api/scans/{scan_id}/findings', response_model=list[Finding])
def get_findings(scan_id: str) -> list[Finding]:
    try:
        return store.get(scan_id).findings
    except KeyError as exc:
        raise HTTPException(status_code=404, detail='Scan not found') from exc


@app.patch('/api/findings/{finding_id}/review', response_model=Finding)
def patch_review(finding_id: str, review: ReviewState) -> Finding:
    try:
        return store.update_finding(finding_id, lambda finding: finding.model_copy(update={'review': review}))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail='Finding not found') from exc


@app.patch('/api/findings/{finding_id}/fix-review', response_model=Finding)
def patch_fix_review(finding_id: str, fix_review: FixReviewState) -> Finding:
    def updater(finding: Finding) -> Finding:
        if finding.review.decision != 'confirmed' and fix_review.decision == 'approved':
            raise HTTPException(status_code=400, detail='Fix approval requires a confirmed finding.')
        return finding.model_copy(update={'fix_review': fix_review})

    try:
        return store.update_finding(finding_id, updater)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail='Finding not found') from exc


@app.get('/api/scans/{scan_id}/report')
def get_report(scan_id: str, format: str = Query('markdown', pattern='^(markdown|json)$')) -> str:
    try:
        record = store.get(scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail='Scan not found') from exc

    status = orchestrator.get_status(scan_id)
    if format == 'json':
        return record.model_dump_json(indent=2)

    lines = [
        f'# Inspection Report: {scan_id}',
        '',
        f'- Target: {record.target_url}',
        f'- Mode: {record.inspection_mode.value}',
        '',
        '## Coverage',
    ]
    for module_name in ModuleName:
        lines.append(f'- {module_name.value}: {status.module_status[module_name].value}')
    lines.extend(['', '## Findings'])
    for finding in record.findings:
        lines.extend(
            [
                f'### {finding.title}',
                f'- Severity: {finding.severity.value}',
                f'- Category: {finding.category.value}',
                f'- Verification: {finding.verification.value}',
                f'- Review: {finding.review.decision.value}',
                f'- Location: {finding.location.file or finding.location.url or "unknown"}',
                f'- Impact: {finding.impact_plain}',
                '',
                '```text',
                (finding.evidence.snippet or '').replace('```', '```text'),
                '```',
                '',
            ]
        )
    return '\n'.join(lines)
