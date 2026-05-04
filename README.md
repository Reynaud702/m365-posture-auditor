# M365 Security Posture Auditor

A read-only Microsoft 365 security audit tool that connects to a tenant via the Microsoft Graph API, runs a battery of security checks, and produces a professional PDF report suitable for delivery to clients.

Built to support a specific service offering: **fixed-fee Microsoft 365 security posture assessments for small and mid-sized businesses** — the kind of engagement that takes 1–2 days and produces a deliverable a CFO or compliance lead can act on.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Read-Only](https://img.shields.io/badge/access-read--only-blue)

## What it checks

The tool runs **17+ checks** across five categories that map directly to the most common Microsoft 365 misconfigurations seen in real BEC investigations and SOC 2 audits.

**Identity & Authentication**
- Legacy / weak authentication methods enabled (SMS, voice, email MFA)
- Global Administrator role hygiene (count, lockout risk)
- Guest invitation policy and guest user permissions
- Stale or never-signed-in privileged accounts (90+ day inactivity)

**Email Security**
- External mail forwarding rules (the #1 BEC indicator)
- Unified audit log enablement
- Shared mailboxes with sign-in not blocked

**Data Sharing (SharePoint / OneDrive)**
- Tenant-wide external sharing capability
- Default link permission (view vs. edit)
- Anonymous link expiration policy

**OAuth Applications**
- User consent policy (legacy "any user can consent" gap)
- Third-party apps holding high-risk permissions (Mail.ReadWrite, Files.ReadWrite.All, etc.)

**Conditional Access**
- Baseline "Require MFA for all users" policy
- Block legacy authentication policy
- Stale Report-only policies

Each finding includes severity, business impact, remediation steps, evidence, and references to CIS Benchmarks and Microsoft documentation.

## Output

The tool produces three artifacts per audit:

- **PDF report** — a professional deliverable with cover page, posture grade (A–F), executive summary, severity-ranked findings, and an appendix of all checks. Suitable to hand directly to a client.
- **Markdown report** — for embedding in tickets, wikis, or version control.
- **JSON** — full structured data for programmatic processing or trend tracking across audits.

## Quickstart

### 1. Install

```bash
git clone https://github.com/<your-username>/m365-posture-auditor.git
cd m365-posture-auditor
pip install -e ".[dev]"
```

### 2. Create an Entra ID app registration in the tenant being audited

The tenant admin needs to create a **read-only** app registration with these Microsoft Graph **Application** permissions:

- `Directory.Read.All`
- `Policy.Read.All`
- `AuditLog.Read.All`
- `Mail.Read` (only required for the external forwarding check)
- `Reports.Read.All`
- `SecurityEvents.Read.All`

The admin must grant admin consent for these permissions.

### 3. Run the audit

```bash
m365audit \
    --tenant-id    <tenant-guid> \
    --client-id    <app-client-guid> \
    --client-secret <secret> \
    --tenant-name  "Acme Corp" \
    --output       ./acme-audit
```

Outputs:

- `acme-audit.pdf` — the deliverable
- `acme-audit.md` — Markdown version
- `acme-audit.json` — full structured data

You can also set `M365_CLIENT_SECRET` as an environment variable instead of passing `--client-secret` on the command line.

### Run only specific checks

```bash
m365audit ... --only ID-001,ID-002,EM-001
```

## Sample finding (from the JSON output)

```json
{
  "check_id": "EM-001",
  "title": "3 mailbox forwarding rule(s) sending to external addresses",
  "severity": "Critical",
  "description": "Inbox rules forward mail to external recipients...",
  "impact": "Sensitive correspondence is being copied outside the organization...",
  "recommendation": "Review every rule with the affected user. Disable any rule the user did not explicitly create...",
  "affected_objects": ["alice@acme.com", "bob@acme.com", "ceo@acme.com"],
  "references": ["Microsoft 365 anti-spam outbound policy", "CIS Microsoft 365 Foundations Benchmark"]
}
```

## Architecture

```
src/m365audit/
├── graph.py              # Auth + paginated Graph client (no SDK dependency)
├── models.py             # Finding, CheckResult, AuditReport dataclasses
├── runner.py             # Orchestrates check execution
├── report_md.py          # Markdown report generator
├── report_pdf.py         # PDF report generator (ReportLab)
├── cli.py                # argparse entry point
└── checks/
    ├── base.py           # Check ABC + registry decorator
    ├── identity.py       # 4 checks: MFA, admin counts, guests, stale admins
    ├── email.py          # 3 checks: forwarding, audit log, shared mailbox sign-in
    ├── sharepoint.py     # 3 sharing-related checks
    ├── oauth.py          # 2 checks: user consent, risky apps
    └── conditional_access.py  # 3 CA baseline checks
```

Adding a new check is straightforward:

```python
from m365audit.checks.base import Check, register
from m365audit.models import Finding, Severity

@register
class MyCheck(Check):
    check_id = "XX-001"
    name = "My check"
    category = "Custom"

    def run(self, client):
        data = client.get("some/endpoint")
        if data.get("bad_setting"):
            return [Finding(
                check_id=self.check_id,
                title="Bad setting detected",
                severity=Severity.HIGH,
                description="...",
                impact="...",
                recommendation="...",
            )]
        return []
```

## Why this exists

If you're a small business running on Microsoft 365, you have three options:

1. Pay an enterprise consultancy $25k+ for a security assessment.
2. Buy a continuous-monitoring SaaS platform (Vanta, Drata, Coreview) for $15k+/year.
3. Hope your MSP set things up correctly five years ago and never touched them again.

Most SMBs default to option 3.

This tool exists to enable a fourth option: a **fixed-fee, 1–2 day Microsoft 365 Security Posture Assessment** delivered by a single practitioner, producing a tangible report that a non-technical decision-maker can act on. The tool does the data-gathering automatically; the practitioner's value is in interpreting findings in business context, prioritizing remediation, and (optionally) implementing the fixes.

## Tests

```bash
pip install -e ".[dev]"
pytest -v
```

Tests use a fake Graph session, so no real tenant access is required to run them.

## Roadmap

- [ ] Defender for Office 365 anti-phishing policy checks (E5 only)
- [ ] Microsoft Secure Score parity check (compares findings against MS's recommendations)
- [ ] Multi-tenant mode — run against a list of tenants and produce a comparative report
- [ ] HTML report with interactive filtering
- [ ] Delta mode — compare today's findings against a previous audit JSON
- [ ] PowerShell wrapper for Exchange-only checks the Graph API doesn't expose
- [ ] Optional integration with Microsoft Sentinel / Defender XDR for incident correlation

## Disclaimer

This is an automated assessment. It is **not** a replacement for a manual review by a qualified security practitioner. Findings should be validated in context before remediation. Some checks rely on Graph API endpoints that are still in beta and may change behavior. The tool is read-only by design and never modifies tenant configuration.

## License

MIT
