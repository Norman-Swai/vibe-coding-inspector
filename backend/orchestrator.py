from __future__ import annotations

import threading
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List

from .analyzers.compliance import run_compliance_analysis
from .analyzers.runtime import run_runtime_analysis
from .analyzers.security import run_security_analysis
from .analyzers.static_analysis import run_static_analysis
from .schemas import (
    Finding,
    ModuleName,
    ModuleState,
    ScanRecord,
    ScanRequest,
    ScanStatusResponse,
    ScanSummary,
    Severity,
)


AnalyzerFn = Callable[[ScanRecord], List[Finding]]


class ScanStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: Dict[str, ScanRecord] = {}

    def create(self, request: ScanRequest) -> ScanRecord:
        record = ScanRecord(
            id=str(uuid.uuid4()),
            target_url=request.target_url,
            repo_path=request.repo_path,
            inspection_mode=request.inspection_mode,
            created_at=datetime.now(timezone.utc).isoformat(),
            module_status={module: ModuleState.queued for module in ModuleName},
        )
        with self._lock:
            self._records[record.id] = record
        return record

    def get(self, scan_id: str) -> ScanRecord:
        with self._lock:
            return self._records[scan_id]

    def save(self, record: ScanRecord) -> None:
        with self._lock:
            self._records[record.id] = record

    def update_finding(self, finding_id: str, updater: Callable[[Finding], Finding]) -> Finding:
        with self._lock:
            for scan_id, record in self._records.items():
                for index, finding in enumerate(record.findings):
                    if finding.id == finding_id:
                        updated = updater(finding)
                        record.findings[index] = updated
                        self._records[scan_id] = record
                        return updated
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
        threading.Thread(target=self._execute_scan, args=(record.id,), daemon=True).start()
        return record

    def _execute_scan(self, scan_id: str) -> None:
        record = self.store.get(scan_id)
        for module_name, analyzer in self.analyzers.items():
            if module_name == ModuleName.static and not record.repo_path:
                record.module_status[module_name] = ModuleState.skipped
                self.store.save(record)
                continue

            record.module_status[module_name] = ModuleState.running
            self.store.save(record)
            try:
                findings = analyzer(record)
                record.findings.extend(findings)
                record.findings = self._deduplicate(record.findings)
                record.module_status[module_name] = ModuleState.done
            except Exception as exc:  # noqa: BLE001
                record.errors[module_name] = str(exc)
                record.module_status[module_name] = ModuleState.failed
            self.store.save(record)

    def _deduplicate(self, findings: Iterable[Finding]) -> List[Finding]:
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
            if key in merged:
                existing = merged[key]
                existing.source_modules = sorted(
                    {*(module for module in existing.source_modules), *(module for module in finding.source_modules)},
                    key=lambda module: module.value,
                )
                if self._severity_rank(finding.severity) < self._severity_rank(existing.severity):
                    existing.severity = finding.severity
                if existing.verification.value == 'hypothesis' and finding.verification.value == 'confirmed':
                    existing.verification = finding.verification
                merged[key] = existing
            else:
                merged[key] = finding
        return list(merged.values())

    @staticmethod
    def _severity_rank(severity: Severity) -> int:
        order = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
        return order.index(severity)

    def get_status(self, scan_id: str) -> ScanStatusResponse:
        record = self.store.get(scan_id)
        severity_counts: Counter[Severity] = Counter({severity: 0 for severity in Severity})
        category_counts: Counter[ModuleName] = Counter({category: 0 for category in ModuleName})
        for finding in record.findings:
            severity_counts[finding.severity] += 1
            category_counts[finding.category] += 1

        summary = ScanSummary(
            total_findings=len(record.findings),
            by_severity={severity: severity_counts[severity] for severity in Severity},
            by_category={category: category_counts[category] for category in ModuleName},
        )
        return ScanStatusResponse(
            id=record.id,
            target_url=record.target_url,
            repo_path=record.repo_path,
            inspection_mode=record.inspection_mode,
            created_at=record.created_at,
            module_status=record.module_status,
            summary=summary,
        )


store = ScanStore()
orchestrator = InspectionOrchestrator(store)
