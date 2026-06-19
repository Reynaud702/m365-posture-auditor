"""CLI entry point for multi-tenant audit mode.

Usage:
    m365audit-multi \
        --tenants tenants.json \
        --output ./reports/ \
        [--only ID-001,CA-001] \
        [--workers 4] \
        [--no-pdf] [--no-md] \
        [--verbose]
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .multi_tenant import (
    load_tenant_configs,
    run_multi_tenant_audit,
    write_multi_tenant_reports,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="m365audit-multi",
        description="Run M365 posture audits against multiple tenants.",
    )
    p.add_argument("--tenants", required=True, type=Path,
                   help="Path to tenants.json configuration file")
    p.add_argument("-o", "--output", type=Path, default=Path("multi-reports"),
                   help="Output directory for all reports (default: ./multi-reports/)")
    p.add_argument("--auditor", default="M365 Posture Auditor")
    p.add_argument("--only", default=None,
                   help="Comma-separated check IDs to run (e.g. 'ID-001,CA-001')")
    p.add_argument("--workers", type=int, default=4,
                   help="Max parallel tenant audits (default: 4)")
    p.add_argument("--no-pdf", action="store_true")
    p.add_argument("--no-md", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    configs = load_tenant_configs(args.tenants)
    if not configs:
        print("error: no tenant configs found in", args.tenants, file=sys.stderr)
        return 2

    missing_secrets = [c for c in configs if not c.client_secret]
    if missing_secrets:
        for c in missing_secrets:
            print(f"error: no client_secret for tenant '{c.tenant_name}' ({c.tenant_id})",
                  file=sys.stderr)
        return 2

    only = [c.strip() for c in args.only.split(",")] if args.only else None

    print(f"[+] Auditing {len(configs)} tenant(s) with up to {args.workers} parallel workers")
    results = run_multi_tenant_audit(configs, auditor=args.auditor, only=only,
                                     max_workers=args.workers)

    succeeded = sum(1 for r in results if r.success)
    failed = len(results) - succeeded
    print(f"[+] Completed: {succeeded} succeeded, {failed} failed")

    for r in results:
        if r.success and r.report:
            print(f"    {r.config.tenant_name}: grade={r.report.posture_grade} "
                  f"score={r.report.risk_score}/100")
        else:
            print(f"    {r.config.tenant_name}: ERROR — {r.error}")

    write_multi_tenant_reports(
        results,
        output_dir=args.output,
        auditor=args.auditor,
        no_pdf=args.no_pdf,
        no_md=args.no_md,
    )
    print(f"[+] Reports written to {args.output}/")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
