"""Data models for audit findings and check results.

A Finding is an individual security issue discovered. A CheckResult wraps
the outcome of running a single check (which can produce 0..N findings).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def order(self) -> int:
        return {
            "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4
        }[self.value]


class Status(str, Enum):
    PASS = "Pass"
    FAIL = "Fail"
    WARN = "Warn"
    ERROR = "Error"
    SKIP = "Skip"


@dataclass
class Finding:
    """A single security issue discovered by a check."""

    check_id: str
    title: str
    severity: Severity
    description: str
    impact: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    affected_objects: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "references": self.references,
            "affected_objects": self.affected_objects,
        }


@dataclass
class CheckResult:
    """Outcome of running a single check."""

    check_id: str
    name: str
    category: str
    status: Status
    findings: list[Finding] = field(default_factory=list)
    error_message: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "category": self.category,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
            "duration_ms": round(self.duration_ms, 1),
        }


@dataclass
class AuditReport:
    """Complete audit report for a tenant."""

    tenant_id: str
    tenant_name: str
    generated_at: datetime
    auditor: str
    results: list[CheckResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.all_findings:
            out[f.severity.value].append(f)
        return out

    @property
    def summary_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> int:
        """0-100 risk score, weighted by severity. Higher = worse."""
        weights = {"Critical": 25, "High": 10, "Medium": 4, "Low": 1, "Informational": 0}
        raw = sum(weights[f.severity.value] for f in self.all_findings)
        # cap at 100
        return min(100, raw)

    @property
    def posture_grade(self) -> str:
        s = self.risk_score
        if s == 0: return "A"
        if s <= 5: return "A-"
        if s <= 15: return "B"
        if s <= 30: return "C"
        if s <= 60: return "D"
        return "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name,
            "generated_at": self.generated_at.isoformat(),
            "auditor": self.auditor,
            "summary": {
                "risk_score": self.risk_score,
                "posture_grade": self.posture_grade,
                "counts": self.summary_counts,
                "checks_run": len(self.results),
                "checks_passed": sum(1 for r in self.results if r.status == Status.PASS),
                "checks_failed": sum(1 for r in self.results if r.status == Status.FAIL),
                "checks_errored": sum(1 for r in self.results if r.status == Status.ERROR),
            },
            "results": [r.to_dict() for r in self.results],
        }


def make_report(tenant_id: str, tenant_name: str, auditor: str = "M365 Posture Auditor") -> AuditReport:
    return AuditReport(
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        generated_at=datetime.now(timezone.utc),
        auditor=auditor,
    )
