"""Multi-tenant audit support.

Allows running the posture auditor against multiple tenants in one invocation
and produces a comparative summary across all of them.

Usage (CLI):
    m365audit-multi --tenants tenants.json --output ./reports/

tenants.json format:
    [
      {
        "tenant_id": "<guid>",
        "client_id": "<guid>",
        "client_secret": "<secret>",   # or omit and set env var M365_SECRET_<ALIAS>
        "tenant_name": "Acme Corp",
        "alias": "acme"               # optional; used in filenames
      },
      ...
    ]

Each tenant gets its own .json / .md / .pdf report. A combined
multi-tenant-summary.json and multi-tenant-summary.md are also written.
"""
from __future__ import annotations

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .graph import GraphClient
from .models import AuditReport
from .runner import run_audit

logger = logging.getLogger(__name__)


@dataclass
class TenantConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    tenant_name: str
    alias: str = ""

    def __post_init__(self):
        if not self.alias:
            # derive a filesystem-safe alias from the tenant name
            self.alias = self.tenant_name.lower().replace(" ", "-").replace("/", "-")[:30]


@dataclass
class MultiTenantResult:
    config: TenantConfig
    report: AuditReport | None = None
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.report is not None


def load_tenant_configs(path: str | Path) -> list[TenantConfig]:
    """Load tenant configs from a JSON file."""
    data = json.loads(Path(path).read_text())
    configs = []
    for entry in data:
        secret = entry.get("client_secret") or ""
        if not secret:
            # Try env var M365_SECRET_<ALIAS_UPPER> or M365_SECRET_<TENANT_ID>
            alias_key = (entry.get("alias") or entry.get("tenant_name", "")).upper().replace(" ", "_")
            secret = (
                os.environ.get(f"M365_SECRET_{alias_key}")
                or os.environ.get(f"M365_SECRET_{entry['tenant_id'].replace('-', '_').upper()}")
                or ""
            )
        configs.append(TenantConfig(
            tenant_id=entry["tenant_id"],
            client_id=entry["client_id"],
            client_secret=secret,
            tenant_name=entry["tenant_name"],
            alias=entry.get("alias", ""),
        ))
    return configs


def audit_tenant(
    config: TenantConfig,
    auditor: str = "M365 Posture Auditor",
    only: list[str] | None = None,
) -> MultiTenantResult:
    """Audit a single tenant. Returns a result regardless of success/failure."""
    logger.info("Starting audit for %s (%s)", config.tenant_name, config.tenant_id)
    try:
        client = GraphClient(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret,
        )
        report = run_audit(client, config.tenant_name, auditor=auditor, only=only)
        logger.info(
            "Completed %s: grade=%s score=%d",
            config.tenant_name, report.posture_grade, report.risk_score,
        )
        return MultiTenantResult(config=config, report=report)
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to audit %s: %s", config.tenant_name, e)
        return MultiTenantResult(config=config, error=str(e))


def run_multi_tenant_audit(
    configs: list[TenantConfig],
    auditor: str = "M365 Posture Auditor",
    only: list[str] | None = None,
    max_workers: int = 4,
) -> list[MultiTenantResult]:
    """Audit multiple tenants in parallel (up to max_workers at once).

    Uses a thread pool because each audit is I/O-bound (Graph API calls).
    max_workers=4 is conservative to avoid Graph rate-limit cascades across
    multiple tenants simultaneously.
    """
    results: list[MultiTenantResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(audit_tenant, cfg, auditor, only): cfg
            for cfg in configs
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)

    # Sort results to match original config order for deterministic output
    order = {cfg.tenant_id: i for i, cfg in enumerate(configs)}
    results.sort(key=lambda r: order.get(r.config.tenant_id, 999))
    return results


def render_multi_summary_json(results: list[MultiTenantResult]) -> dict[str, Any]:
    """Produce a structured summary dict suitable for JSON output."""
    tenants = []
    for r in results:
        if r.report:
            tenants.append({
                "tenant_name": r.config.tenant_name,
                "tenant_id": r.config.tenant_id,
                "alias": r.config.alias,
                "posture_grade": r.report.posture_grade,
                "risk_score": r.report.risk_score,
                "summary_counts": r.report.summary_counts,
                "checks_run": len(r.report.results),
                "generated_at": r.report.generated_at.isoformat(),
            })
        else:
            tenants.append({
                "tenant_name": r.config.tenant_name,
                "tenant_id": r.config.tenant_id,
                "alias": r.config.alias,
                "error": r.error,
            })

    successful = [t for t in tenants if "error" not in t]
    return {
        "audit_type": "multi-tenant",
        "tenant_count": len(results),
        "successful": len(successful),
        "failed": len(results) - len(successful),
        "tenants": tenants,
    }


def render_multi_summary_markdown(results: list[MultiTenantResult]) -> str:
    out: list[str] = []
    out.append("# Multi-Tenant M365 Security Posture Summary\n\n")

    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    out.append(f"**Tenants audited:** {len(results)} "
               f"({len(successful)} succeeded, {len(failed)} failed)\n\n")

    if successful:
        out.append("## Posture by Tenant\n\n")
        out.append("| Tenant | Grade | Score | Critical | High | Medium | Low |\n")
        out.append("|--------|-------|-------|----------|------|--------|-----|\n")
        for r in successful:
            assert r.report is not None
            c = r.report.summary_counts
            out.append(
                f"| {r.config.tenant_name} | **{r.report.posture_grade}** "
                f"| {r.report.risk_score}/100 "
                f"| {c['Critical']} | {c['High']} | {c['Medium']} | {c['Low']} |\n"
            )
        out.append("\n")

        # Highlight worst findings across all tenants
        all_findings = [
            (f, r.config.tenant_name)
            for r in successful
            for f in r.report.all_findings  # type: ignore[union-attr]
            if f.severity.value in ("Critical", "High")
        ]
        if all_findings:
            out.append("## Critical and High Findings Across All Tenants\n\n")
            for f, tenant_name in sorted(all_findings, key=lambda x: x[0].severity.order):
                out.append(f"- **[{f.severity.value}]** `{f.check_id}` {f.title} "
                            f"— _{tenant_name}_\n")
            out.append("\n")

    if failed:
        out.append("## Failed Audits\n\n")
        for r in failed:
            out.append(f"- **{r.config.tenant_name}** (`{r.config.tenant_id}`): {r.error}\n")
        out.append("\n")

    out.append("---\n_Report generated by m365-posture-auditor multi-tenant mode._\n")
    return "".join(out)


def write_multi_tenant_reports(
    results: list[MultiTenantResult],
    output_dir: Path,
    auditor: str = "M365 Posture Auditor",
    no_pdf: bool = False,
    no_md: bool = False,
) -> None:
    """Write per-tenant reports and the combined summary to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)

    for result in results:
        if not result.report:
            continue
        base = output_dir / result.config.alias
        report = result.report

        json_path = base.with_suffix(".json")
        json_path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        logger.info("Wrote %s", json_path)

        if not no_md:
            from .report_md import render_markdown
            md_path = base.with_suffix(".md")
            md_path.write_text(render_markdown(report))
            logger.info("Wrote %s", md_path)

        if not no_pdf:
            try:
                from .report_pdf import render_pdf
                pdf_path = base.with_suffix(".pdf")
                render_pdf(report, str(pdf_path))
                logger.info("Wrote %s", pdf_path)
            except ImportError:
                pass

    # Combined summary
    summary_json_path = output_dir / "multi-tenant-summary.json"
    summary_json_path.write_text(
        json.dumps(render_multi_summary_json(results), indent=2, default=str)
    )
    logger.info("Wrote %s", summary_json_path)

    if not no_md:
        summary_md_path = output_dir / "multi-tenant-summary.md"
        summary_md_path.write_text(render_multi_summary_markdown(results))
        logger.info("Wrote %s", summary_md_path)
