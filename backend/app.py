from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from .orchestrator import orchestrator, store
from .schemas import (
    SEVERITY_ORDER,
    FixReviewDecision,
    FixReviewState,
    Finding,
    InspectionMode,
    ModuleName,
    ReviewDecision,
    ReviewState,
    ScanRecord,
    ScanRequest,
    ScanStartResponse,
    ScanStatusResponse,
)

LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'}
# The UI is served through the Vite proxy, so cross-origin access is only needed for local tooling.
# Never use "*": any website a user visits could otherwise start repo scans and read their findings.
DEFAULT_CORS_ORIGINS = 'http://localhost:5173,http://127.0.0.1:5173'

app = FastAPI(title='Vibe Coding Inspector', version='0.2.0')
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.environ.get('INSPECTOR_CORS_ORIGINS', DEFAULT_CORS_ORIGINS).split(',') if origin.strip()],
    allow_methods=['GET', 'POST', 'PATCH'],
    allow_headers=['Content-Type'],
)


def _validate_request(payload: ScanRequest) -> None:
    parsed = urlparse(payload.target_url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise HTTPException(status_code=400, detail='Enter a full http:// or https:// URL.')
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=400, detail='Authorization confirmation is required.')
    if payload.inspection_mode == InspectionMode.localhost and parsed.hostname not in LOCAL_HOSTS:
        raise HTTPException(status_code=400, detail='Localhost mode only accepts localhost, 127.0.0.1, or [::1].')
    if payload.repo_path:
        if payload.inspection_mode == InspectionMode.public_readonly:
            raise HTTPException(status_code=400, detail='Repository analysis is only available in localhost mode.')
        repo = Path(payload.repo_path)
        if not repo.is_absolute():
            raise HTTPException(status_code=400, detail='Repository path must be absolute.')
        if not repo.is_dir():
            raise HTTPException(status_code=400, detail=f'Repository path is not a directory: {payload.repo_path}')


@app.post('/api/scans', response_model=ScanStartResponse)
def start_scan(payload: ScanRequest) -> ScanStartResponse:
    payload.repo_path = (payload.repo_path or '').strip() or None
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
    if review.decision in {ReviewDecision.rejected, ReviewDecision.escalated} and not (review.reason or '').strip():
        raise HTTPException(status_code=400, detail='Rejecting or escalating a finding requires a reason.')

    def updater(finding: Finding) -> Finding:
        update: dict = {'review': review}
        # A fix can only stay approved while its finding is confirmed.
        if review.decision != ReviewDecision.confirmed and finding.fix_review and finding.fix_review.decision == FixReviewDecision.approved:
            update['fix_review'] = FixReviewState()
        return finding.model_copy(update=update)

    try:
        return store.update_finding(finding_id, updater)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail='Finding not found') from exc


@app.patch('/api/findings/{finding_id}/fix-review', response_model=Finding)
def patch_fix_review(finding_id: str, fix_review: FixReviewState) -> Finding:
    def updater(finding: Finding) -> Finding:
        if finding.review.decision != ReviewDecision.confirmed and fix_review.decision == FixReviewDecision.approved:
            raise HTTPException(status_code=400, detail='Fix approval requires a confirmed finding.')
        return finding.model_copy(update={'fix_review': fix_review})

    try:
        return store.update_finding(finding_id, updater)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail='Finding not found') from exc


@app.get('/api/scans/{scan_id}/report')
def get_report(scan_id: str, format: str = Query('markdown', pattern='^(markdown|json)$')) -> Response:
    try:
        record = store.get(scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail='Scan not found') from exc

    if format == 'json':
        return Response(record.model_dump_json(indent=2), media_type='application/json')
    return Response(render_markdown(record), media_type='text/markdown; charset=utf-8')


def _fence(text: str) -> str:
    """A code fence longer than any backtick run inside the evidence, so captured text cannot break out of it."""
    longest = max((len(run) for run in re.findall(r'`+', text)), default=0)
    fence = '`' * max(3, longest + 1)
    return f'{fence}text\n{text}\n{fence}'


def _location(finding: Finding) -> str:
    location = finding.location
    if location.file:
        lines = f':{location.line_start}' if location.line_start else ''
        return f'{location.file}{lines}'
    if location.url:
        detail = f' (line {location.line_start})' if location.line_start else ''
        element = f' — {location.element}' if location.element else ''
        return f'{location.url}{detail}{element}'
    return 'unknown'


def render_markdown(record: ScanRecord) -> str:
    findings = sorted(record.findings, key=lambda finding: SEVERITY_ORDER.index(finding.severity))
    counts = {severity: sum(1 for finding in findings if finding.severity == severity) for severity in SEVERITY_ORDER}
    lines = [
        f'# Inspection report — {record.target_url}',
        '',
        f'- Scan ID: `{record.id}`',
        f'- Mode: {record.inspection_mode.value}',
        f'- Repository: {record.repo_path or "not provided"}',
        f'- Started: {record.created_at}',
        f'- Finished: {record.finished_at or "still running"}',
        f'- Limits: {record.options.max_pages} pages, {record.options.timeout_seconds:g}s request timeout',
        f'- Findings: {len(findings)} (' + ', '.join(f'{severity.value} {count}' for severity, count in counts.items()) + ')',
        '',
        '## Coverage',
        '',
        '| Module | State | Scanned | Duration | Notes |',
        '| --- | --- | --- | --- | --- |',
    ]
    for module in ModuleName:
        report = record.modules[module]
        scanned = f'{report.scanned} {report.scanned_label}'.strip() if report.state.value == 'done' else '—'
        duration = f'{report.duration_ms} ms' if report.duration_ms is not None else '—'
        notes = '; '.join([*([f'ERROR: {report.error}'] if report.error else []), *report.notes]) or '—'
        lines.append(f'| {module.value} | {report.state.value} | {scanned} | {duration} | {notes.replace("|", "/")} |')

    lines.extend(['', '## Findings', ''])
    if not findings:
        lines.append('No findings were reported by the modules that completed.')
    for index, finding in enumerate(findings, start=1):
        review = finding.review
        review_text = review.decision.value + (f' by {review.reviewer}' if review.reviewer else '') + (f' — {review.reason}' if review.reason else '')
        fix_text = finding.fix_review.decision.value if finding.fix_review else 'pending'
        lines.extend(
            [
                f'### {index}. {finding.title}',
                '',
                f'- Severity: **{finding.severity.value}** · Verification: {finding.verification.value} · Category: {finding.category.value}',
                f'- Location: {_location(finding)}',
                f'- Check: {finding.evidence.check or "—"}',
                f'- Evidence source: {finding.evidence.captured_output or "—"}',
                f'- Occurrences: {finding.evidence.occurrences}',
                *([f'- CWE: {finding.cwe_id}'] if finding.cwe_id else []),
                f'- Review: {review_text}',
                f'- Fix review: {fix_text}',
                '',
                finding.description_plain,
                '',
                f'**Impact:** {finding.impact_plain}',
                '',
                _fence(finding.evidence.snippet or '(no excerpt)'),
                '',
                *([f'**Suggested fix:** {finding.fix_suggestion.summary}', ''] if finding.fix_suggestion else []),
            ]
        )
    return '\n'.join(lines)
