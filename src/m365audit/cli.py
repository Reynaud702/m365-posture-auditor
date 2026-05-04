"""Command-line interface for the M365 Posture Auditor.

Usage:
    m365audit \\
        --tenant-id <guid> \\
        --client-id <guid> \\
        --client-secret <secret> \\
        --tenant-name "Acme Corp" \\
        --output ./acme-report

Reads credentials from --client-secret OR the M365_CLIENT_SECRET env var.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .graph import GraphClient
from .report_md import render_markdown
from .runner import run_audit


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="m365audit",
        description="Read-only Microsoft 365 security posture audit.",
    )
    p.add_argument("--tenant-id", required=True, help="Microsoft 365 tenant GUID")
    p.add_argument("--client-id", required=True, help="App registration client GUID")
    p.add_argument(
        "--client-secret", default=None,
        help="App secret. If omitted, reads from M365_CLIENT_SECRET env var.",
    )
    p.add_argument("--tenant-name", required=True, help="Friendly tenant name for the report cover")
    p.add_argument("--auditor", default="M365 Posture Auditor", help="Name shown on the report")
    p.add_argument(
        "-o", "--output", type=Path, default=Path("m365-report"),
        help="Output basename (writes <basename>.json, <basename>.md, <basename>.pdf)",
    )
    p.add_argument(
        "--only", default=None,
        help="Comma-separated list of check IDs to run (e.g. 'ID-001,EM-001')",
    )
    p.add_argument("--no-pdf", action="store_true", help="Skip PDF generation")
    p.add_argument("--no-md", action="store_true", help="Skip Markdown generation")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def run(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    secret = args.client_secret or os.environ.get("M365_CLIENT_SECRET")
    if not secret:
        print("error: provide --client-secret or set M365_CLIENT_SECRET", file=sys.stderr)
        return 2

    only = [c.strip() for c in args.only.split(",")] if args.only else None

    print(f"[+] Connecting to tenant {args.tenant_id} as app {args.client_id}")
    client = GraphClient(
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        client_secret=secret,
    )

    print(f"[+] Running audit against {args.tenant_name}")
    report = run_audit(client, args.tenant_name, auditor=args.auditor, only=only)

    print(f"[+] Audit complete. Posture grade: {report.posture_grade}, "
          f"risk score: {report.risk_score}/100")
    counts = report.summary_counts
    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        if counts[sev]:
            print(f"    {sev:14s} {counts[sev]}")

    json_path = args.output.with_suffix(".json")
    json_path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
    print(f"[+] Wrote {json_path}")

    if not args.no_md:
        md_path = args.output.with_suffix(".md")
        md_path.write_text(render_markdown(report))
        print(f"[+] Wrote {md_path}")

    if not args.no_pdf:
        try:
            from .report_pdf import render_pdf
            pdf_path = args.output.with_suffix(".pdf")
            render_pdf(report, str(pdf_path))
            print(f"[+] Wrote {pdf_path}")
        except ImportError:
            print("    (PDF generation skipped: install with `pip install m365audit[pdf]`)",
                  file=sys.stderr)

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
