"""NIST CSF 2.0 control mapping."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class CsfControl:
    function: str
    function_name: str
    category: str
    category_name: str
    subcategory: str
    description: str
    def label(self): return f"{self.subcategory}: {self.description}"

_MAPPINGS = {
    "TM-001":[CsfControl("PR","Protect","PR.AA","Identity Management","PR.AA-05","Access permissions and authorizations are managed")],
    "TM-002":[CsfControl("PR","Protect","PR.AA","Identity Management","PR.AA-05","Access permissions and authorizations are managed")],
    "TM-003":[CsfControl("PR","Protect","PR.AA","Identity Management","PR.AA-03","Users, services, and hardware are authenticated")],
    "TR-001":[CsfControl("PR","Protect","PR.DS","Data Security","PR.DS-02","The confidentiality and integrity of data-in-transit are protected")],
    "TR-002":[CsfControl("PR","Protect","PR.PS","Platform Security","PR.PS-01","Configuration management practices are established and applied")],
    "TR-003":[CsfControl("PR","Protect","PR.PS","Platform Security","PR.PS-01","Configuration management practices are established and applied")],
    "DF-001":[CsfControl("PR","Protect","PR.PS","Platform Security","PR.PS-01","Configuration management practices are established and applied")],
    "DF-002":[CsfControl("PR","Protect","PR.PS","Platform Security","PR.PS-01","Configuration management practices are established and applied")],
    "DF-003":[CsfControl("PR","Protect","PR.PS","Platform Security","PR.PS-01","Configuration management practices are established and applied")],
    "CA-001":[CsfControl("PR","Protect","PR.AA","Identity Management","PR.AA-03","Users, services, and hardware are authenticated")],
    "CA-002":[CsfControl("PR","Protect","PR.AA","Identity Management","PR.AA-03","Users, services, and hardware are authenticated")],
}

def get_controls(check_id): return _MAPPINGS.get(check_id, [])

def csf_summary(check_ids):
    functions, subcategories = {}, set()
    for cid in check_ids:
        for ctrl in get_controls(cid):
            functions.setdefault(ctrl.function_name, set()).add(ctrl.subcategory)
            subcategories.add(ctrl.subcategory)
    return {"total_subcategories_covered":len(subcategories),
        "by_function":{fn:sorted(subs) for fn,subs in sorted(functions.items())}}

def render_csf_appendix(check_ids):
    out = ["## Appendix: NIST CSF 2.0 Control Mapping\n\n","| Check ID | CSF Subcategory | Description |\n|---|---|---|\n"]
    seen = set()
    for cid in sorted(set(check_ids)):
        for ctrl in get_controls(cid):
            if (cid, ctrl.subcategory) not in seen:
                seen.add((cid, ctrl.subcategory))
                out.append(f"| `{cid}` | `{ctrl.subcategory}` | {ctrl.description} |\n")
    if not seen: out.append("| — | — | No mapped checks found |\n")
    return "".join(out)
