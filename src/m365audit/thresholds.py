"""Severity threshold configuration."""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from .models import AuditReport, CheckResult, Finding, Severity

_SEVERITY_RANK = {"Critical":0,"High":1,"Medium":2,"Low":3,"Informational":4}
_GRADE_RANK = {"A":0,"A-":1,"B":2,"C":3,"D":4,"F":5}

@dataclass
class ThresholdConfig:
    minimum_severity: str = "Informational"
    suppressed_checks: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    fail_on_grade: str | None = None

    @classmethod
    def from_file(cls, path):
        return cls.from_dict(json.loads(Path(path).read_text()))

    @classmethod
    def from_dict(cls, data):
        return cls(minimum_severity=data.get("minimum_severity","Informational"),
            suppressed_checks=data.get("suppressed_checks",[]),
            severity_overrides=data.get("severity_overrides",{}),
            fail_on_grade=data.get("fail_on_grade"))

    def is_suppressed(self, check_id): return check_id in self.suppressed_checks

    def meets_minimum_severity(self, severity):
        return _SEVERITY_RANK.get(severity.value,99) <= _SEVERITY_RANK.get(self.minimum_severity,4)

    def apply_override(self, finding):
        override = self.severity_overrides.get(finding.check_id)
        if override and override in _SEVERITY_RANK:
            return Finding(check_id=finding.check_id,title=finding.title,severity=Severity(override),
                description=finding.description,impact=finding.impact,recommendation=finding.recommendation,
                evidence={**finding.evidence,"_severity_overridden":True},references=finding.references,
                affected_objects=finding.affected_objects)
        return finding

    def grade_fails(self, grade):
        if not self.fail_on_grade: return False
        return _GRADE_RANK.get(grade,5) > _GRADE_RANK.get(self.fail_on_grade,5)

def apply_thresholds(report, config):
    from .models import make_report, Status
    filtered = make_report(report.tenant_id, report.tenant_name, auditor=report.auditor)
    filtered.generated_at = report.generated_at
    for result in report.results:
        if config.is_suppressed(result.check_id): continue
        ff = [config.apply_override(f) for f in result.findings if config.meets_minimum_severity(config.apply_override(f).severity)]
        if ff:
            status = Status.WARN if all(f.severity.value in ("Low","Informational") for f in ff) else Status.FAIL
        elif result.status.value == "Error": status = result.status
        else: status = Status.PASS
        filtered.results.append(CheckResult(check_id=result.check_id,name=result.name,category=result.category,
            status=status,findings=ff,error_message=result.error_message,duration_ms=result.duration_ms))
    return filtered

def default_config(): return ThresholdConfig()
