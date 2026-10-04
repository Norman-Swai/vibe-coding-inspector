from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import Counter, OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, TypeVar

from .analyzers.common import AnalyzerResult, ScanError
from .analyzers.compliance import run_compliance_analysis
from .analyzers.runtime import run_runtime_analysis
from .analyzers.security import run_security_analysis
from .analyzers.static_analysis import run_static_analysis
from .context import ScanContext
from .schemas import (
    SEVERITY_ORDER,
    ActivityEvent,
    ActivityKind,
    ActivityPage,
    Finding,
    ModuleName,
    ModuleReport,
    ModuleState,
    ScanOptions,
    ScanRecord,
    ScanRequest,
    ScanState,
    ScanStatusResponse,
    ScanSummary,
    Severity,
    Verification,
)

logger = logging.getLogger(__name__)
T = TypeVar('T')

AnalyzerFn = Callable[[ScanContext], AnalyzerResult]
MAX_STORED_SCANS = 50
MAX_EVENTS_PER_SCAN = 2000
MAX_ACTIVITY_CHARS_PER_SCAN = 2_000_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanStore:
    """In-memory scan storage. Readers get deep copies so they never observe a half-applied update."""

    def __init__(self, max_scans: int = MAX_STORED_SCANS) -> None:
        self._lock = threading.Lock()
        self._records: OrderedDict[str, ScanRecord] = OrderedDict()
        self._activity_chars: Dict[str, int] = {}
        self._max_scans = max_scans

    def create(self, request: ScanRequest) -> ScanRecord:
        record = ScanRecord(
            id=str(uuid.uuid4()),
            target_url=request.target_url,
            repo_path=request.repo_path,
            inspection_mode=request.inspection_mode,
            options=ScanOptions(max_pages=request.max_pages, timeout_seconds=request.timeout_seconds),
            created_at=_now(),
            modules={module: ModuleReport() for module in ModuleName},
        )
        with self._lock:
            self._records[record.id] = record
            while len(self._records) > self._max_scans:
                evicted, _ = self._records.popitem(last=False)
                self._activity_chars.pop(evicted, None)
        return record.model_copy(deep=True)

    def get(self, scan_id: str) -> ScanRecord:
        with self._lock:
            return self._records[scan_id].model_copy(deep=True)

    def mutate(self, scan_id: str, change: Callable[[ScanRecord], None]) -> None:
        with self._lock:
            change(self._records[scan_id])

    def read(self, scan_id: str, view: Callable[[ScanRecord], T]) -> T:
        """Run ``view`` under the lock; it must copy whatever it returns."""
        with self._lock:
            return view(self._records[scan_id])

    def append_event(self, scan_id: str, event: ActivityEvent) -> None:
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                return
            record.last_activity = event.message
            request = event.request
            size = len(event.message) + len(event.output or '') + (len(request.url) + len(request.final_url or '') if request else 0)
            used = self._activity_chars.get(scan_id, 0)
            if len(record.activity) < MAX_EVENTS_PER_SCAN and used + size <= MAX_ACTIVITY_CHARS_PER_SCAN:
                record.activity.append(event)
                self._activity_chars[scan_id] = used + size
            else:
                record.activity_dropped += 1

    def activity_since(self, scan_id: str, since: int) -> ActivityPage:
        with self._lock:
            record = self._records[scan_id]
            events = [event.model_copy(deep=True) for event in record.activity if event.seq > since]
            return ActivityPage(events=events, next_seq=events[-1].seq if events else since, dropped=record.activity_dropped)

    def update_finding(self, finding_id: str, updater: Callable[[Finding], Finding]) -> Finding:
        with self._lock:
            for record in self._records.values():
                for index, finding in enumerate(record.findings):
                    if finding.id == finding_id:
                        updated = updater(finding)
                        record.findings[index] = updated
                        return updated.model_copy(deep=True)
        raise KeyError(finding_id)


class InspectionOrchestrator:
    def __init__(self, store: ScanStore) -> None:
        self.store = store
        self.analyzers: Dict[ModuleName, AnalyzerFn] = {
            ModuleName.runtime: run_runtime_analysis,
            ModuleName.static: run_static_analysis,
            ModuleName.security: run_security_analysis,
            ModuleName.compliance: run_compliance_analysis,
        }

    def start_scan(self, request: ScanRequest) -> ScanRecord:
        record = self.store.create(request)
        threading.Thread(target=self.execute_scan, args=(record.id,), daemon=True, name=f'scan-{record.id[:8]}').start()
        return record

    def execute_scan(self, scan_id: str) -> None:
        record = self.store.get(scan_id)
        context = ScanContext(record, sink=lambda event: self.store.append_event(scan_id, event))
        started = time.perf_counter()
        context.emit(
            None,
            ActivityKind.step,
            f'Scan started: {record.target_url} ({record.inspection_mode.value} mode)',
            '\n'.join(
                [
                    f'repository: {record.repo_path or "not provided"}',
                    f'max pages: {record.options.max_pages}',
                    f'request timeout: {record.options.timeout_seconds:g} s',
                    f'modules: {", ".join(module.value for module in self.analyzers)} (run in parallel)',
                ]
            ),
        )
        try:
            with ThreadPoolExecutor(max_workers=len(self.analyzers), thread_name_prefix='module') as pool:
                for module, analyzer in self.analyzers.items():
                    skip_reason = self._skip_reason(module, context)
                    if skip_reason:
                        self._set_report(scan_id, module, ModuleReport(state=ModuleState.skipped, notes=[skip_reason]))
                        context.emit(module, ActivityKind.step, f'{module.value} skipped: {skip_reason}')
                    else:
                        pool.submit(self._run_module, scan_id, module, analyzer, context)
        finally:
            context.close()
            total = self.store.read(scan_id, lambda r: len(r.findings))
            context.emit(None, ActivityKind.result, f'Scan completed in {int((time.perf_counter() - started) * 1000)} ms: {total} finding(s)')

            def finish(record: ScanRecord) -> None:
                record.status = ScanState.completed
                record.finished_at = _now()

            self.store.mutate(scan_id, finish)

    @staticmethod
    def _skip_reason(module: ModuleName, context: ScanContext) -> Optional[str]:
        if module == ModuleName.static and context.repo_path is None:
            return 'No repository path was provided, so source code was not analysed.'
        return None

    def _run_module(self, scan_id: str, module: ModuleName, analyzer: AnalyzerFn, context: ScanContext) -> None:
        report = ModuleReport(state=ModuleState.running, started_at=_now())
        self._set_report(scan_id, module, report)
        context.emit(module, ActivityKind.step, f'{module.value} module started')
        started = time.perf_counter()
        result: Optional[AnalyzerResult] = None
        try:
            result = analyzer(context)
        except ScanError as exc:
            report.error = str(exc)
        except Exception as exc:  # noqa: BLE001 - a module failure must be visible, never silently "0 issues"
            logger.exception('Module %s failed for scan %s', module.value, scan_id)
            report.error = f'Internal error in {module.value} module: {type(exc).__name__}: {exc}'

        report.finished_at = _now()
        report.duration_ms = int((time.perf_counter() - started) * 1000)
        if result is None:
            report.state = ModuleState.failed
            self._set_report(scan_id, module, report)
            context.emit(module, ActivityKind.error, f'{module.value} module failed after {report.duration_ms} ms: {report.error}')
            return

        report.state = ModuleState.done
        report.scanned = result.scanned
        report.scanned_label = result.scanned_label
        report.notes = result.notes

        def apply(record: ScanRecord) -> None:
            record.findings = deduplicate([*record.findings, *result.findings])
            record.modules[module] = report

        self.store.mutate(scan_id, apply)
        context.emit(
            module,
            ActivityKind.result,
            f'{module.value} module done in {report.duration_ms} ms: {len(result.findings)} finding(s), scanned {report.scanned_label or report.scanned}',
        )

    def _set_report(self, scan_id: str, module: ModuleName, report: ModuleReport) -> None:
        snapshot = report.model_copy(deep=True)

        def change(record: ScanRecord) -> None:
            record.modules[module] = snapshot

        self.store.mutate(scan_id, change)

    def get_status(self, scan_id: str) -> ScanStatusResponse:
        return self.store.read(scan_id, build_status)


def build_status(record: ScanRecord) -> ScanStatusResponse:
    """Status without findings or the activity log, so polling stays cheap. Runs under the store lock."""
    severity_counts = Counter(finding.severity for finding in record.findings)
    category_counts = Counter(finding.category for finding in record.findings)
    modules = {module: report.model_copy(deep=True) for module, report in record.modules.items()}
    return ScanStatusResponse(
        id=record.id,
        target_url=record.target_url,
        repo_path=record.repo_path,
        inspection_mode=record.inspection_mode,
        options=record.options.model_copy(),
        status=record.status,
        created_at=record.created_at,
        finished_at=record.finished_at,
        module_status={module: report.state for module, report in modules.items()},
        modules=modules,
        summary=ScanSummary(
            total_findings=len(record.findings),
            by_severity={severity: severity_counts[severity] for severity in Severity},
            by_category={category: category_counts[category] for category in ModuleName},
        ),
        activity_count=len(record.activity) + record.activity_dropped,
        last_activity=record.last_activity,
    )


def deduplicate(findings: Iterable[Finding]) -> List[Finding]:
    """Merge findings that describe the same issue at the same place, keeping the strongest severity/verification."""
    merged: Dict[str, Finding] = {}
    for finding in findings:
        key = '|'.join(
            [
                finding.category.value,
                finding.title,
                finding.location.file or finding.location.url or '',
                str(finding.location.line_start or ''),
            ]
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        existing.source_modules = sorted({*existing.source_modules, *finding.source_modules}, key=lambda module: module.value)
        if SEVERITY_ORDER.index(finding.severity) < SEVERITY_ORDER.index(existing.severity):
            existing.severity = finding.severity
        if finding.verification == Verification.confirmed:
            existing.verification = Verification.confirmed
    return list(merged.values())


store = ScanStore()
orchestrator = InspectionOrchestrator(store)
