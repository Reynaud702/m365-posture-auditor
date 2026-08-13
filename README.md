# M365 Security Posture Auditor

**Author:** Reynaud Hunter  
**GitHub:** [Reynaud702/m365-posture-auditor](https://github.com/Reynaud702/m365-posture-auditor)  
**Contact:** reynaud702@outlook.com 
**Commercial Licensing:** Available — contact the author for pricing

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-BUSL--1.1-orange)
![Read-Only](https://img.shields.io/badge/access-read--only-blue)
![Tests](https://img.shields.io/badge/tests-91%20passing-brightgreen)

---

## What This Is

The M365 Security Posture Auditor is a read-only Microsoft 365 security audit tool built and owned by Reynaud Hunter. It connects to a Microsoft 365 tenant via the Microsoft Graph API, runs a battery of security checks across identity, email, data sharing, OAuth applications, Conditional Access, Microsoft Teams, and Exchange mail transport rules, and produces a professional report suitable for delivery to clients.

This tool was developed as original intellectual property through independent research at Oregon State University and through hands-on security operations work at ORTSOC, Oregon State's security operations center, where real client assessments for K-12 schools and municipal governments informed every design decision.

This is not a generic open source project. It is the foundation of a fixed-fee Microsoft 365 security assessment service offered by the author. If you are an organization interested in an assessment, or a practitioner interested in licensing the tool commercially, see the service and licensing sections below.

---

## The Problem This Solves

Small businesses, school districts, and local governments running Microsoft 365 have three options when it comes to security assessments:

1. Pay an enterprise consultancy $25,000 or more for a full security review.
2. Subscribe to a continuous monitoring SaaS platform like Vanta or Drata for $15,000 or more per year.
3. Hope their MSP set things up correctly years ago and never touched them since.

Most default to option 3. The result is that the organizations least equipped to handle a breach are also the least likely to know they are vulnerable.

This tool exists to make a fourth option possible: a fixed-fee, one to two day Microsoft 365 Security Posture Assessment delivered by a single practitioner, producing a clear report that a superintendent, city manager, or CFO can actually act on. The tool handles the data gathering automatically. The practitioner's value is in interpreting the findings in business context, prioritizing remediation based on the client's resources and risk tolerance, and optionally implementing the fixes.

---

## The Service

### Who This Is For

This service is designed specifically for organizations that are under-resourced for security but still responsible for protecting sensitive data. That includes:

- K-12 school districts managing student records under FERPA
- Municipal governments handling personally identifiable information
- Nonprofits and community organizations using Microsoft 365
- Small and mid-sized businesses that cannot afford enterprise security vendors

### What You Get

Every engagement produces three deliverables:

A PDF report with a cover page, posture grade from A to F, executive summary written for non-technical leadership, severity-ranked findings with business impact descriptions, step-by-step remediation guidance, and an appendix of all checks run. This is something you can hand directly to a school board, city council, or executive team.

A Markdown report for embedding in internal wikis, ticketing systems, or documentation.

A JSON data file with full structured output for tracking trends across multiple audits over time.

### Service Tiers

**Basic Assessment — contact for pricing**  
A single Microsoft 365 tenant, one automated scan, PDF report with findings and recommendations, and a 30 minute debrief call. Designed for organizations under 500 users that need a clear picture of their current posture without a large consulting engagement.

**Full Assessment — contact for pricing**  
Everything in the Basic Assessment plus a NIST CSF 2.0 gap analysis mapped directly to the findings, a prioritized remediation roadmap, a 90 day follow-up scan to measure improvement, and a written summary suitable for presenting to leadership or a board.

**Managed Posture Monitoring — contact for pricing**  
A recurring monthly assessment with trend reporting showing how posture changes over time, delta reporting that surfaces new findings and resolved issues since the last scan, and a quarterly review call. This is designed for organizations that want ongoing visibility without hiring a full-time security analyst.

### How an Engagement Works

1. You provide read-only API credentials for your Microsoft 365 tenant. The tool never writes to or modifies your environment.
2. The tool runs the full check suite against your tenant, typically completing in under five minutes.
3. You receive your report within two business days along with a scheduled debrief call.
4. Findings are explained in plain language with specific remediation steps tailored to your organization's resources.
5. Optional: the author can implement the recommended fixes directly or work alongside your IT team.

---

## What It Checks

The tool runs checks across seven categories covering the most common Microsoft 365 misconfigurations seen in real breach investigations and compliance audits.

**Identity and Authentication**
- Legacy and weak authentication methods enabled including SMS, voice, and email MFA
- Global Administrator role hygiene including count and lockout risk
- Guest invitation policy and guest user permissions
- Stale or never signed-in privileged accounts with 90 or more days of inactivity

**Email Security**
- External mail forwarding rules which are the number one indicator of business email compromise
- Unified audit log enablement
- Shared mailboxes with sign-in not blocked

**Data Sharing**
- Tenant-wide external sharing capability in SharePoint and OneDrive
- Default link permission set to edit instead of view
- Anonymous link expiration policy

**OAuth Applications**
- User consent policy allowing any user to grant third-party app access
- Third-party apps holding high-risk permissions including Mail.ReadWrite and Files.ReadWrite.All

**Conditional Access**
- Baseline policy requiring MFA for all users
- Policy blocking legacy authentication
- Stale report-only policies that provide no actual protection

**Microsoft Teams Security**
- External access federation open to all external domains
- Guest users permitted to be group owners
- Anonymous meeting join enabled without lobby enforcement

**Exchange Mail Transport Rules**
- External auto-forwarding not blocked at the tenant level
- Transport rules configured to bypass spam and malware filtering
- Sender whitelists that undermine DMARC and anti-spoofing enforcement

Each finding includes severity level, business impact written for a non-technical audience, specific remediation steps, evidence from the tenant, and references to CIS Benchmarks and Microsoft documentation.

---

## NIST CSF 2.0 Alignment

Every check in the tool is mapped to the relevant NIST Cybersecurity Framework 2.0 subcategory. This makes the audit output directly usable as evidence in a CSF-based risk assessment, which is the framework used by ORTSOC for K-12 and municipal government client engagements. Organizations working toward NIST CSF alignment can use the assessment report as a starting point for their Protect and Detect function gap analysis.

---

## Quickstart for Practitioners

### Install

```bash
git clone https://github.com/Reynaud702/m365-posture-auditor.git
cd m365-posture-auditor
pip install -e ".[dev]"
```

### Create an Entra ID App Registration

The tenant admin needs to create a read-only app registration with these Microsoft Graph Application permissions:

- Directory.Read.All
- Policy.Read.All
- AuditLog.Read.All
- Mail.Read (required for the external forwarding check)
- Reports.Read.All
- SecurityEvents.Read.All

The admin must grant admin consent for these permissions. The tool never requests write permissions.

### Run the Audit

```bash
m365audit \
    --tenant-id     <tenant-guid> \
    --client-id     <app-client-guid> \
    --client-secret <secret> \
    --tenant-name   "Acme School District" \
    --output        ./acme-audit
```

This produces three files: acme-audit.pdf, acme-audit.md, and acme-audit.json.

You can also set M365_CLIENT_SECRET as an environment variable instead of passing it on the command line.

### Run Only Specific Checks

```bash
m365audit ... --only ID-001,ID-002,EM-001
```

### Multi-Tenant Mode

```bash
m365audit --tenants tenants.json --output ./reports/
```

Audits all tenants in the config file concurrently and produces a combined summary report alongside individual tenant reports.

### Delta Mode

```bash
m365audit ... --baseline ./previous-audit.json
```

Compares the current audit against a previous run and surfaces new findings, resolved findings, and score changes since the last assessment.

---

## Sample Finding

```json
{
  "check_id": "EM-001",
  "title": "3 mailbox forwarding rule(s) sending to external addresses",
  "severity": "Critical",
  "description": "Inbox rules are forwarding mail to external recipients without the users' knowledge.",
  "impact": "Sensitive correspondence is being copied outside the organization in real time. This is the most common indicator of an active business email compromise.",
  "recommendation": "Review every rule with the affected user. Disable any rule the user did not explicitly create. Enable the outbound spam filter policy to block auto-forwarding at the tenant level.",
  "affected_objects": ["alice@acme.com", "bob@acme.com", "ceo@acme.com"],
  "references": ["CIS Microsoft 365 Foundations Benchmark v3.0", "Microsoft 365 anti-spam outbound policy documentation"]
}
```

---

## Architecture

src/m365audit/
├── graph.py # Auth and paginated Graph client with no SDK dependency
├── models.py # Finding, CheckResult, AuditReport dataclasses
├── runner.py # Orchestrates check execution
├── report_md.py # Markdown report generator
├── report_pdf.py # PDF report generator using ReportLab
├── report_html.py # Self-contained HTML report generator
├── report_html.py # HTML report renderer
├── thresholds.py # Client-configurable severity threshold system
├── history.py # Snapshot history and trend tracking
├── csf_mapping.py # NIST CSF 2.0 control mappings for all checks
├── multi_tenant.py # Parallel multi-tenant audit runner
├── delta.py # Delta comparison between audit runs
├── cli.py # argparse entry point
└── checks/
├── base.py # Check base class and registry decorator
├── identity.py # 4 checks
├── email.py # 3 checks
├── sharepoint.py # 3 checks
├── oauth.py # 2 checks
├── conditional_access.py # 3 checks
├── defender.py # 3 Defender for Office 365 checks
├── teams.py # 3 Microsoft Teams checks
└── transport.py # 3 Exchange transport rule checks


---

## Intellectual Property and Licensing

This tool is original intellectual property created by Reynaud Hunter. It was developed through independent research at Oregon State University and through practical security operations experience at ORTSOC.

**Non-commercial and educational use** is permitted under the Business Source License 1.1. This includes academic research, student learning, and non-profit educational institutions using the tool for internal assessment purposes.

**Commercial use** requires a separate written license from the author. Commercial use includes any use where the tool or its output is part of a paid service, any use by a for-profit organization assessing its own or a client's environment, and any use by a managed service provider or consulting firm.

For commercial licensing inquiries contact the author directly at reynaud702@outlook.com.

Unauthorized commercial use is a violation of the license terms.

---

## Tests

```bash
pip install -e ".[dev]"
pytest -v
```

91 tests covering all check categories, report renderers, multi-tenant mode, delta mode, threshold configuration, snapshot history, and NIST CSF 2.0 mappings. Tests use a mock Graph session so no real tenant access is required.

---

## Roadmap

- [ ] Microsoft Secure Score parity check comparing findings against Microsoft's own recommendations
- [ ] HTML report with interactive severity filtering
- [ ] PowerShell wrapper for Exchange-only checks the Graph API does not expose
- [ ] Optional integration with Microsoft Sentinel and Defender XDR for incident correlation
- [ ] Web-based report viewer for sharing findings with clients without sending a file

---

## Disclaimer

This is an automated assessment tool. It is not a replacement for a manual review by a qualified security practitioner. Findings should be validated in context before remediation. Some checks rely on Microsoft Graph API endpoints that are in beta and may change behavior. The tool is read-only by design and never modifies tenant configuration.

---

*Built by Reynaud Hunter. All rights reserved for commercial use.*
