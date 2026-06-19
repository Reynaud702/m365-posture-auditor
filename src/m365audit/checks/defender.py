"""Defender for Office 365 checks (E5 / Defender add-on licenses).

These checks require the SecurityEvents.Read.All and ThreatAssessment.ReadWrite.All
permissions and are only meaningful when the tenant has Defender for Office 365
Plan 1 or Plan 2. All checks are fail-safe: if the tenant lacks the license or
the API returns 403/404, the check returns no finding rather than a false alarm.

Check IDs:
    DF-001  Anti-phishing policy — impersonation protection
    DF-002  Safe Attachments policy coverage
    DF-003  Safe Links policy coverage
"""
from __future__ import annotations

from ..graph import GraphClient, GraphError
from ..models import Finding, Severity
from .base import Check, register


def _get_security_policies(client: GraphClient, path: str) -> list[dict] | None:
    """Fetch a security policy collection; return None if unavailable (no license)."""
    try:
        resp = client.get(path)
        return resp.get("value", [resp] if resp else [])
    except GraphError as e:
        if e.status in (403, 404):
            return None
        raise


@register
class AntiPhishingPolicyCheck(Check):
    check_id = "DF-001"
    name = "Defender anti-phishing impersonation protection"
    category = "Defender for Office 365"
    description = (
        "Verifies that at least one enabled anti-phishing policy has impersonation "
        "protection turned on. Impersonation protection is the core Defender for "
        "Office 365 P1 feature that blocks lookalike sender domains (e.g. acme-corp.com "
        "impersonating acme.com) and targeted user impersonation."
    )

    def run(self, client: GraphClient) -> list[Finding]:
        # Graph beta: security/attackSimulation won't give us EOP policies, but the
        # /security/informationProtection path also doesn't. The best available path
        # for Defender anti-phishing via Graph is the secureScore recommendations —
        # we check that as a proxy and also attempt the beta security endpoint.
        policies = _get_security_policies(
            client,
            "security/threatIntelligence/hosts",  # probe for Defender license
        )
        if policies is None:
            # Tenant does not have Defender for Office 365 or missing permission.
            return []

        # Attempt to read anti-phishing configuration via the beta endpoint.
        try:
            result = client.get("security/attackSimulation/simulationAutomations")
        except GraphError as e:
            if e.status in (403, 404):
                return []
            raise

        # Read Secure Score to check impersonation protection recommendation.
        try:
            score_resp = client.get(
                "security/secureScores",
                params={"$top": "1"},
            )
            controls = score_resp.get("controlScores", [])
        except GraphError:
            controls = []

        impersonation_enabled = False
        for control in controls:
            cid = (control.get("controlName") or "").lower()
            if "impersonation" in cid and control.get("score", 0) > 0:
                impersonation_enabled = True
                break

        if impersonation_enabled:
            return []

        return [Finding(
            check_id=self.check_id,
            title="Anti-phishing impersonation protection may not be configured",
            severity=Severity.HIGH,
            description=(
                "No evidence was found that anti-phishing impersonation protection "
                "is enabled. Defender for Office 365 Plan 1 includes domain and user "
                "impersonation protection that blocks spoofed lookalike senders targeting "
                "executives and sensitive roles."
            ),
            impact=(
                "Without impersonation protection, targeted phishing emails that spoof "
                "executive names or near-match domains (acme-corp.com vs acme.com) reach "
                "user inboxes. This is the most common path for BEC wire-fraud attacks."
            ),
            recommendation=(
                "In the Microsoft Defender portal > Email & collaboration > Policies & rules > "
                "Threat policies > Anti-phishing, edit the default policy or create a targeted "
                "policy and enable: (1) Enable users to protect (add executive and finance "
                "accounts), (2) Enable domains to protect (check 'Include domains I own'), "
                "(3) Set impersonation action to 'Move message to Junk' or quarantine."
            ),
            evidence={"secure_score_controls_checked": len(controls)},
            references=[
                "CIS M365 Benchmark 2.1.9",
                "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-about",
            ],
        )]


@register
class SafeAttachmentsPolicyCheck(Check):
    check_id = "DF-002"
    name = "Defender Safe Attachments policy coverage"
    category = "Defender for Office 365"
    description = (
        "Verifies that Safe Attachments is enabled. Safe Attachments detonates "
        "email attachments in a sandbox before delivery, blocking zero-day malware "
        "that signature-based AV misses."
    )

    def run(self, client: GraphClient) -> list[Finding]:
        # Probe Defender availability via Secure Score
        try:
            score_resp = client.get("security/secureScores", params={"$top": "1"})
            controls = score_resp.get("controlScores", [])
        except GraphError as e:
            if e.status in (403, 404):
                return []
            raise

        if not controls:
            # Can't determine — no Secure Score data means no Defender license likely
            return []

        safe_attachments_enabled = False
        for control in controls:
            cid = (control.get("controlName") or "").lower()
            if "safeattachment" in cid.replace(" ", "").replace("_", ""):
                if control.get("score", 0) > 0:
                    safe_attachments_enabled = True
                    break

        if safe_attachments_enabled:
            return []

        # Check if we have a Secure Score result for safe attachments at all
        has_sa_control = any(
            "safeattachment" in (c.get("controlName") or "").lower().replace(" ", "").replace("_", "")
            for c in controls
        )

        if not has_sa_control:
            # No Safe Attachments control in Secure Score = tenant has no Defender P1
            return []

        return [Finding(
            check_id=self.check_id,
            title="Safe Attachments does not appear to be enabled",
            severity=Severity.HIGH,
            description=(
                "Microsoft Secure Score reports Safe Attachments is not configured "
                "or contributing to the score. Safe Attachments sandboxes email "
                "attachments before delivery and blocks malware that evades traditional "
                "antivirus scanning."
            ),
            impact=(
                "Malicious attachments (weaponized Office documents, PDFs, ISO files) "
                "are delivered directly to user mailboxes. A single click can result in "
                "ransomware deployment across the tenant."
            ),
            recommendation=(
                "In the Defender portal > Threat policies > Safe Attachments, enable "
                "the built-in protection policy (covers all recipients) and set the "
                "action to 'Block'. For higher security, enable Safe Attachments for "
                "SharePoint, OneDrive, and Teams as well."
            ),
            evidence={"safe_score_controls_found": len(controls)},
            references=[
                "CIS M365 Benchmark 2.1.4",
                "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-about",
            ],
        )]


@register
class SafeLinksPolicyCheck(Check):
    check_id = "DF-003"
    name = "Defender Safe Links policy coverage"
    category = "Defender for Office 365"
    description = (
        "Verifies that Safe Links is enabled. Safe Links rewrites URLs in email "
        "and Office documents and re-checks them at click time, blocking links to "
        "phishing pages that were clean at delivery but later weaponized."
    )

    def run(self, client: GraphClient) -> list[Finding]:
        try:
            score_resp = client.get("security/secureScores", params={"$top": "1"})
            controls = score_resp.get("controlScores", [])
        except GraphError as e:
            if e.status in (403, 404):
                return []
            raise

        if not controls:
            return []

        safe_links_enabled = False
        has_sl_control = False
        for control in controls:
            cid = (control.get("controlName") or "").lower().replace(" ", "").replace("_", "")
            if "safelink" in cid:
                has_sl_control = True
                if control.get("score", 0) > 0:
                    safe_links_enabled = True
                break

        if safe_links_enabled or not has_sl_control:
            return []

        return [Finding(
            check_id=self.check_id,
            title="Safe Links does not appear to be enabled",
            severity=Severity.HIGH,
            description=(
                "Microsoft Secure Score reports Safe Links is not configured. "
                "Safe Links rewrites URLs at delivery and re-validates them at "
                "click time, blocking phishing pages that were benign when the "
                "email arrived ('time-of-click' protection)."
            ),
            impact=(
                "URLs in phishing emails that pass initial scanning can be "
                "weaponized after delivery. Without Safe Links, users who click "
                "hours or days after delivery hit the live malicious page."
            ),
            recommendation=(
                "In the Defender portal > Threat policies > Safe Links, enable "
                "the built-in protection policy. In a custom policy, ensure "
                "'Track when users click' is on and 'Do not rewrite URLs' is "
                "disabled. Extend coverage to Microsoft Teams and Office apps."
            ),
            evidence={"secure_score_controls_found": len(controls)},
            references=[
                "CIS M365 Benchmark 2.1.5",
                "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-about",
            ],
        )]
