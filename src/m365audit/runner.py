"""Audit runner — executes all registered checks against a tenant."""
from __future__ import annotations

import logging

from .checks import all_checks
from .graph import GraphClient
from .models import AuditReport, make_report

logger = logging.getLogger(__name__)


def run_audit(
    client: GraphClient,
    tenant_name: str,
    auditor: str = "M365 Posture Auditor",
    only: list[str] | None = None,
) -> AuditReport:
    """Run every registered check (or only those whose check_id is in `only`).

    Args:
        client: an authenticated GraphClient
        tenant_name: human-friendly name shown on the report cover page
        auditor: name displayed in the report header
        only: optional list of check_id values to run (e.g. ['ID-001', 'EM-001'])

    Returns:
        Populated AuditReport.
    """
    report = make_report(client.tenant_id, tenant_name, auditor=auditor)
    checks = all_checks()
    if only:
        wanted = set(only)
        checks = [c for c in checks if c.check_id in wanted]
    logger.info("Running %d checks", len(checks))
    for check in checks:
        logger.info("Running %s: %s", check.check_id, check.name)
        result = check.execute(client)
        report.results.append(result)
    return report
