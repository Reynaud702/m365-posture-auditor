"""Conditional Access policy checks.

CA policies are M365's primary defense-in-depth layer. The most impactful
findings here are missing baseline policies: no MFA enforcement, no block on
legacy auth, no risk-based policies.
"""
from __future__ import annotations

from ..graph import GraphClient
from ..models import Finding, Severity
from .base import Check, register


@register
class CABaselinePoliciesCheck(Check):
    check_id = "CA-001"
    name = "Conditional Access baseline policies"
    category = "Conditional Access"
    description = "Verifies the existence of baseline CA policies (MFA, block legacy auth)."

    def run(self, client: GraphClient) -> list[Finding]:
        try:
            policies = list(client.get_all("identity/conditionalAccess/policies"))
        except Exception:
            return [Finding(
                check_id=self.check_id,
                title="Could not enumerate Conditional Access policies",
                severity=Severity.HIGH,
                description="Conditional Access requires Entra ID P1 or P2. Either the tenant lacks the required license or the app registration is missing Policy.Read.All.",
                impact="Without CA, the tenant relies on per-user MFA and security defaults, which provide far weaker enforcement.",
                recommendation="If Entra ID P1/P2 is licensed, grant Policy.Read.All to the audit app and re-run. Otherwise note the licensing gap.",
                evidence={},
                references=["Microsoft: Conditional Access overview"],
            )]

        findings: list[Finding] = []
        enabled_policies = [p for p in policies if p.get("state") == "enabled"]

        # Check 1: any policy that requires MFA for all users on all cloud apps
        has_baseline_mfa = False
        has_block_legacy = False

        for p in enabled_policies:
            conditions = p.get("conditions") or {}
            grant_controls = (p.get("grantControls") or {})
            built_in_controls = grant_controls.get("builtInControls") or []
            client_app_types = (conditions.get("clientAppTypes") or [])
            users = conditions.get("users") or {}
            apps = conditions.get("applications") or {}

            include_users = users.get("includeUsers") or []
            include_apps = apps.get("includeApplications") or []

            covers_all_users = "All" in include_users
            covers_all_apps = "All" in include_apps

            if (covers_all_users and covers_all_apps and "mfa" in built_in_controls
                    and "all" in client_app_types or "browser" in client_app_types):
                has_baseline_mfa = True

            # Block legacy: a policy that targets exchangeActiveSync or other
            # client app types and grants no access (block).
            if "block" in built_in_controls and any(
                c in client_app_types for c in ("exchangeActiveSync", "other")
            ):
                has_block_legacy = True

        if not has_baseline_mfa:
            findings.append(Finding(
                check_id=self.check_id,
                title="No baseline 'Require MFA for all users' policy detected",
                severity=Severity.CRITICAL,
                description="No enabled Conditional Access policy enforces MFA for all users across all cloud apps.",
                impact="Password-only authentication is permitted. Credential stuffing, phishing, and password spray succeed against any account without per-user MFA.",
                recommendation="Create a CA policy: Users = All users (exclude break-glass), Cloud apps = All cloud apps, Grant = Require MFA. Ramp via Report-only mode for one week first.",
                evidence={"enabled_policies_count": len(enabled_policies)},
                references=["Microsoft: CA template - Require MFA for all users"],
            ))

        if not has_block_legacy:
            findings.append(Finding(
                check_id=self.check_id,
                title="No policy blocking legacy authentication",
                severity=Severity.HIGH,
                description="No CA policy was found that blocks legacy auth client app types (Exchange ActiveSync, other clients).",
                impact="Legacy clients bypass MFA entirely. They are the most common path for password-spray attacks to succeed even on accounts that 'have MFA'.",
                recommendation="Create a CA policy: Users = All users, Cloud apps = All, Conditions > Client apps = Exchange ActiveSync clients + Other clients, Grant = Block. Test in Report-only first.",
                evidence={},
                references=["Microsoft: Block legacy authentication with Conditional Access"],
            ))

        # Check 2: CA policies in Report-only mode that have been there forever
        # are a soft signal — flag them for review.
        report_only = [p.get("displayName") for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]
        if len(report_only) > 5:
            findings.append(Finding(
                check_id=self.check_id,
                title=f"{len(report_only)} Conditional Access policies stuck in Report-only mode",
                severity=Severity.LOW,
                description="Many CA policies remain in Report-only. Report-only is intended as a temporary testing state.",
                impact="Policies that should be enforcing controls are only being logged.",
                recommendation="Review each report-only policy. Promote to Enabled or remove.",
                evidence={"report_only_policies": report_only},
                references=[],
            ))

        return findings
