"""Delta / trending mode.

Compares a current AuditReport against a previous audit's JSON output and
produces a structured diff showing:

  - New findings (appeared since last audit)
  - Resolved findings (present before, gone now)
  - Persisting findings (still present)
  - Score and grade change

Usage:
    m365audit ... --baseline ./previous-audit.json --output ./new-audit

The delta is appended to the JSON output and written as a separate
<output>-delta.md file alongside the normal report artifacts.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AuditReport, Finding, Severity


# ──────────────────────────────────────────────────────────────────────────────
# Stable identity key for a finding
# ──────────────────────────────────────────────────────────────────────────────

def _finding_key(f: Finding) -> str:
    """A stable key that identifies a finding across runs.

    We use check_id + severity + a normalised title (lowercase, no punctuation).
    We intentionally do NOT include affected_objects because the set of affected
    accounts can change while the root misconfiguration persists.
    """
    norm_title = "".join(c for c in f.title.lower() if c.isalnum() or c == " ").strip()
    return f"{f.check_id}::{f.severity.value}::{norm_title}"


def _finding_key_from_dict(d: dict[str, Any]) -> str:
    norm_title = "".join(c for c in (d.get("title") or "").lower() if c.isalnum() or c == " ").strip()
    return f"{d.get('check_id', '')}::{d.get('severity', '')}::{norm_title}"


# ──────────────────────────────────────────────────────────────────────────────
# Delta dataclass
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class FindingDelta:
    """Represents one finding that changed status between two audits."""
    key: str
    check_id: str
    title: str
    severity: str
    status: str  # "new" | "resolved" | "persisting"
    baseline_affected: list[str] = field(default_factory=list)
    current_affected: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "baseline_affected": self.baseline_affected,
            "current_affected": self.current_affected,
        }


@dataclass
class AuditDelta:
    """Full diff between two audit runs."""
    tenant_id: str
    tenant_name: str
    baseline_generated_at: str
    current_generated_at: str
    baseline_grade: str
    current_grade: str
    baseline_score: int
    current_score: int
    new_findings: list[FindingDelta] = field(default_factory=list)
    resolved_findings: list[FindingDelta] = field(default_factory=list)
    persisting_findings: list[FindingDelta] = field(default_factory=list)

    @property
    def score_change(self) -> int:
        return self.current_score - self.baseline_score

    @property
    def improved(self) -> bool:
        return self.current_score < self.baseline_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name,
            "baseline_generated_at": self.baseline_generated_at,
            "current_generated_at": self.current_generated_at,
            "baseline_grade": self.baseline_grade,
            "current_grade": self.current_grade,
            "baseline_score": self.baseline_score,
            "current_score": self.current_score,
            "score_change": self.score_change,
            "new_findings_count": len(self.new_findings),
            "resolved_findings_count": len(self.resolved_findings),
            "persisting_findings_count": len(self.persisting_findings),
            "new_findings": [f.to_dict() for f in self.new_findings],
            "resolved_findings": [f.to_dict() for f in self.resolved_findings],
            "persisting_findings": [f.to_dict() for f in self.persisting_findings],
        }


# ──────────────────────────────────────────────────────────────────────────────
# Core diff logic
# ──────────────────────────────────────────────────────────────────────────────

def compute_delta(current: AuditReport, baseline_path: str | Path) -> AuditDelta:
    """Compare current report against a previously-saved JSON baseline.

    Args:
        current: The just-completed AuditReport.
        baseline_path: Path to the JSON file from a previous audit run.

    Returns:
        AuditDelta describing what changed.
    """
    baseline_data = json.loads(Path(baseline_path).read_text())
    baseline_summary = baseline_data.get("summary", {})

    # Build lookup of baseline findings by stable key
    baseline_findings: dict[str, dict] = {}
    for result in baseline_data.get("results", []):
        for f in result.get("findings", []):
            k = _finding_key_from_dict(f)
            baseline_findings[k] = f

    # Build lookup of current findings by stable key
    current_findings: dict[str, Finding] = {}
    for f in current.all_findings:
        k = _finding_key(f)
        current_findings[k] = f

    baseline_keys = set(baseline_findings.keys())
    current_keys = set(current_findings.keys())

    new_keys = current_keys - baseline_keys
    resolved_keys = baseline_keys - current_keys
    persisting_keys = baseline_keys & current_keys

    def _sev_order(sev: str) -> int:
        return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}.get(sev, 5)

    def _from_current(k: str) -> FindingDelta:
        f = current_findings[k]
        return FindingDelta(
            key=k,
            check_id=f.check_id,
            title=f.title,
            severity=f.severity.value,
            status="new",
            current_affected=list(f.affected_objects),
        )

    def _from_baseline(k: str) -> FindingDelta:
        d = baseline_findings[k]
        return FindingDelta(
            key=k,
            check_id=d.get("check_id", ""),
            title=d.get("title", ""),
            severity=d.get("severity", ""),
            status="resolved",
            baseline_affected=list(d.get("affected_objects", [])),
        )

    def _persisting(k: str) -> FindingDelta:
        f = current_findings[k]
        d = baseline_findings[k]
        return FindingDelta(
            key=k,
            check_id=f.check_id,
            title=f.title,
            severity=f.severity.value,
            status="persisting",
            baseline_affected=list(d.get("affected_objects", [])),
            current_affected=list(f.affected_objects),
        )

    new = sorted([_from_current(k) for k in new_keys], key=lambda x: _sev_order(x.severity))
    resolved = sorted([_from_baseline(k) for k in resolved_keys], key=lambda x: _sev_order(x.severity))
    persisting = sorted([_persisting(k) for k in persisting_keys], key=lambda x: _sev_order(x.severity))

    return AuditDelta(
        tenant_id=current.tenant_id,
        tenant_name=current.tenant_name,
        baseline_generated_at=baseline_data.get("generated_at", "unknown"),
        current_generated_at=current.generated_at.isoformat(),
        baseline_grade=baseline_summary.get("posture_grade", "?"),
        current_grade=current.posture_grade,
        baseline_score=baseline_summary.get("risk_score", 0),
        current_score=current.risk_score,
        new_findings=new,
        resolved_findings=resolved,
        persisting_findings=persisting,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Markdown delta report
# ──────────────────────────────────────────────────────────────────────────────

_SEV_BADGE = {
    "Critical": "🔴", "High": "🟠", "Medium": "🟡",
    "Low": "🔵", "Informational": "⚪",
}


def render_delta_markdown(delta: AuditDelta) -> str:
    out: list[str] = []
    out.append(f"# M365 Posture Delta Report — {delta.tenant_name}\n\n")

    direction = "📈 Regressed" if delta.score_change > 0 else ("📉 Improved" if delta.score_change < 0 else "➡️ Unchanged")
    out.append(f"**{direction}**\n\n")
    out.append("| | Baseline | Current | Change |\n|---|---|---|---|\n")
    change_str = (f"+{delta.score_change}" if delta.score_change > 0 else str(delta.score_change))
    out.append(f"| **Grade** | {delta.baseline_grade} | {delta.current_grade} | — |\n")
    out.append(f"| **Risk Score** | {delta.baseline_score}/100 | {delta.current_score}/100 | {change_str} |\n")
    out.append(f"| **New findings** | — | {len(delta.new_findings)} | — |\n")
    out.append(f"| **Resolved findings** | — | {len(delta.resolved_findings)} | — |\n")
    out.append(f"| **Persisting findings** | — | {len(delta.persisting_findings)} | — |\n\n")

    out.append(f"Baseline taken: `{delta.baseline_generated_at}`  \n")
    out.append(f"Current audit: `{delta.current_generated_at}`\n\n")

    if delta.new_findings:
        out.append("## 🆕 New Findings\n\n")
        out.append("These issues were not present in the previous audit.\n\n")
        for f in delta.new_findings:
            badge = _SEV_BADGE.get(f.severity, "")
            out.append(f"- {badge} **[{f.severity}]** `{f.check_id}` — {f.title}\n")
            if f.current_affected:
                shown = f.current_affected[:5]
                out.append(f"  Affected: {', '.join(f'`{o}`' for o in shown)}")
                if len(f.current_affected) > 5:
                    out.append(f" +{len(f.current_affected) - 5} more")
                out.append("\n")
        out.append("\n")

    if delta.resolved_findings:
        out.append("## ✅ Resolved Findings\n\n")
        out.append("These issues existed in the previous audit and are no longer detected.\n\n")
        for f in delta.resolved_findings:
            badge = _SEV_BADGE.get(f.severity, "")
            out.append(f"- {badge} **[{f.severity}]** `{f.check_id}` — {f.title}\n")
        out.append("\n")

    if delta.persisting_findings:
        out.append("## ⚠️ Persisting Findings\n\n")
        out.append("These issues have not been remediated since the last audit.\n\n")
        for f in delta.persisting_findings:
            badge = _SEV_BADGE.get(f.severity, "")
            out.append(f"- {badge} **[{f.severity}]** `{f.check_id}` — {f.title}\n")
            # Show if affected object count changed
            if f.baseline_affected and f.current_affected:
                diff = len(f.current_affected) - len(f.baseline_affected)
                if diff != 0:
                    sign = "+" if diff > 0 else ""
                    out.append(f"  _(affected count: {sign}{diff})_\n")
        out.append("\n")

    out.append("---\n_Delta generated by m365-posture-auditor. "
               "Resolved findings should be verified manually before closing._\n")
    return "".join(out)
