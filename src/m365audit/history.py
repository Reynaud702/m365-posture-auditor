"""Snapshot history manager."""
from __future__ import annotations
import json, re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .models import AuditReport

@dataclass
class SnapshotMeta:
    path: Path
    tenant_id: str
    tenant_name: str
    generated_at: datetime
    posture_grade: str
    risk_score: int
    finding_counts: dict[str, int]

class SnapshotStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _tenant_dir(self, tenant_id):
        d = self.root / re.sub(r"[^a-zA-Z0-9\-]","_",tenant_id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save(self, report):
        ts = report.generated_at.strftime("%Y%m%dT%H%M%SZ")
        name = re.sub(r"[^a-zA-Z0-9\-]","_",report.tenant_name)[:30]
        path = self._tenant_dir(report.tenant_id) / f"{ts}_{name}.json"
        path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        return path

    def list_snapshots(self, tenant_id):
        metas = []
        for p in sorted(self._tenant_dir(tenant_id).glob("*.json")):
            try:
                data = json.loads(p.read_text())
                summary = data.get("summary", {})
                metas.append(SnapshotMeta(path=p,tenant_id=data.get("tenant_id",tenant_id),
                    tenant_name=data.get("tenant_name",""),
                    generated_at=datetime.fromisoformat(data.get("generated_at",datetime.now(timezone.utc).isoformat())),
                    posture_grade=summary.get("posture_grade","?"),risk_score=summary.get("risk_score",0),
                    finding_counts=summary.get("counts",{})))
            except (json.JSONDecodeError, KeyError): continue
        return metas

    def latest_baseline(self, tenant_id, skip=1):
        s = self.list_snapshots(tenant_id)
        return None if len(s) <= skip else s[-(skip+1)].path

    def prune(self, tenant_id, keep=12):
        s = self.list_snapshots(tenant_id)
        to_delete = s[:-keep] if len(s) > keep else []
        deleted = []
        for m in to_delete:
            m.path.unlink(missing_ok=True)
            deleted.append(m.path)
        return deleted

    def trend_summary(self, tenant_id):
        s = self.list_snapshots(tenant_id)
        if not s: return {"tenant_id":tenant_id,"snapshots":0,"trend":[]}
        trend = [{"date":m.generated_at.strftime("%Y-%m-%d"),"posture_grade":m.posture_grade,
            "risk_score":m.risk_score,"findings":m.finding_counts} for m in s]
        delta = s[-1].risk_score - s[0].risk_score
        return {"tenant_id":tenant_id,"tenant_name":s[-1].tenant_name,"snapshots":len(s),
            "first_audit":s[0].generated_at.isoformat(),"latest_audit":s[-1].generated_at.isoformat(),
            "first_grade":s[0].posture_grade,"latest_grade":s[-1].posture_grade,
            "first_score":s[0].risk_score,"latest_score":s[-1].risk_score,
            "score_delta":delta,"improved":delta<0,"trend":trend}

    def trend_markdown(self, tenant_id):
        summary = self.trend_summary(tenant_id)
        if not summary["trend"]: return f"No snapshots found for tenant `{tenant_id}`.\n"
        delta = summary["score_delta"]
        direction = "Improved" if delta < 0 else ("Regressed" if delta > 0 else "Unchanged")
        out = [f"# Posture Trend — {summary.get('tenant_name',tenant_id)}\n\n"]
        out.append(f"**Snapshots:** {summary['snapshots']}  \n**Overall trend:** {direction}\n\n")
        out.append("| Date | Grade | Risk Score |\n|------|-------|------------|\n")
        for e in summary["trend"]:
            out.append(f"| {e['date']} | **{e['posture_grade']}** | {e['risk_score']}/100 |\n")
        return "".join(out)
