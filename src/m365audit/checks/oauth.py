"""OAuth application and consent checks.

Malicious OAuth apps are a growing initial-access vector. This check looks for
risky consent grants and over-privileged third-party apps.
"""
from __future__ import annotations

from ..graph import GraphClient
from ..models import Finding, Severity
from .base import Check, register


# Permissions that are most often abused by malicious OAuth apps
HIGH_RISK_PERMISSIONS = {
    "Mail.ReadWrite",
    "Mail.Read",
    "Mail.ReadWrite.All",
    "Mail.Send",
    "Mail.Send.Shared",
    "MailboxSettings.ReadWrite",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    "Directory.ReadWrite.All",
    "Application.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "User.ReadWrite.All",
}


@register
class UserConsentPolicyCheck(Check):
    check_id = "OA-001"
    name = "User consent to applications policy"
    category = "OAuth Apps"
    description = "Users should not be able to consent to high-risk app permissions."

    def run(self, client: GraphClient) -> list[Finding]:
        try:
            policy = client.get("policies/authorizationPolicy")
        except Exception:
            return []

        # default value: allow user consent for verified publishers / low-impact only
        default_user_role = policy.get("defaultUserRolePermissions") or {}
        # The relevant property is permissionGrantPoliciesAssigned on user-default
        grants = default_user_role.get("permissionGrantPoliciesAssigned") or []

        findings: list[Finding] = []
        # If users can grant consent to ANY app (no admin review), that's a finding.
        # The "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" id allows broad consent.
        if any("legacy" in (g or "").lower() for g in grants):
            findings.append(Finding(
                check_id=self.check_id,
                title="Users can consent to any third-party application",
                severity=Severity.HIGH,
                description="The tenant uses the legacy user consent policy: any user can grant any app any delegated permission, with no admin review.",
                impact="A phishing campaign that lures users into consenting to a malicious OAuth app obtains persistent mailbox access without ever stealing a password — bypassing MFA entirely.",
                recommendation="In Entra ID > Enterprise applications > Consent and permissions > User consent settings, set 'User consent for applications' to either 'Do not allow user consent' or 'Allow user consent for apps from verified publishers, for selected permissions'. Enable the admin consent workflow.",
                evidence={"permissionGrantPoliciesAssigned": grants},
                references=["Microsoft: Configure user consent settings", "CIS M365 5.1.5"],
            ))
        return findings


@register
class HighRiskOAuthAppsCheck(Check):
    check_id = "OA-002"
    name = "Third-party OAuth apps with high-risk permissions"
    category = "OAuth Apps"
    description = "Inventories enterprise apps with mailbox or directory write permissions."

    def run(self, client: GraphClient) -> list[Finding]:
        # Enumerate service principals (each represents an app instance in the tenant)
        risky_apps: list[dict] = []
        for sp in client.get_all(
            "servicePrincipals",
            params={
                "$select": "id,displayName,appId,publisherName,verifiedPublisher,signInAudience,tags",
                "$filter": "servicePrincipalType eq 'Application'",
            },
        ):
            sp_id = sp["id"]
            try:
                grants = list(client.get_all(f"servicePrincipals/{sp_id}/oauth2PermissionGrants"))
                app_role_assignments = list(
                    client.get_all(f"servicePrincipals/{sp_id}/appRoleAssignments")
                )
            except Exception:
                continue

            # Collect the granted permission scopes
            scopes: set[str] = set()
            for g in grants:
                for s in (g.get("scope") or "").split():
                    scopes.add(s)

            high_risk = scopes & HIGH_RISK_PERMISSIONS
            if high_risk:
                risky_apps.append({
                    "name": sp.get("displayName"),
                    "app_id": sp.get("appId"),
                    "publisher": sp.get("publisherName") or "(unknown)",
                    "verified": bool(sp.get("verifiedPublisher")),
                    "high_risk_permissions": sorted(high_risk),
                })

        if not risky_apps:
            return []

        unverified = [a for a in risky_apps if not a["verified"]]
        severity = Severity.HIGH if unverified else Severity.MEDIUM

        return [Finding(
            check_id=self.check_id,
            title=f"{len(risky_apps)} third-party app(s) hold high-risk permissions",
            severity=severity,
            description=f"Apps with delegated permissions to read/write mail, files, or directory data. {len(unverified)} are from unverified publishers.",
            impact="Compromise of any of these apps (or their developers) grants the attacker the same access to the tenant. Unverified-publisher apps are higher risk.",
            recommendation="Review each app. For any unrecognized app or unverified publisher, revoke the consent. For legitimate apps, document the business justification.",
            evidence={"apps": risky_apps[:20], "total": len(risky_apps)},
            references=["Microsoft: Investigate risky OAuth apps"],
            affected_objects=[a["name"] for a in risky_apps if a["name"]],
        )]
