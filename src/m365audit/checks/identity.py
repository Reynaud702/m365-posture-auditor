"""Identity & authentication checks.

These are the highest-value findings for almost every M365 audit. The vast
majority of M365 breaches start with a credential compromise; misconfigurations
in this category are typically what made the compromise possible.
"""
from __future__ import annotations

from ..graph import GraphClient
from ..models import Finding, Severity
from .base import Check, register

REF_CIS = "CIS Microsoft 365 Foundations Benchmark"
REF_GRAPH_AUTH = "https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethodspolicy"


@register
class LegacyAuthEnabledCheck(Check):
    check_id = "ID-001"
    name = "Legacy authentication protocols enabled"
    category = "Identity"
    description = (
        "Legacy auth protocols (POP, IMAP, SMTP AUTH, basic auth) bypass "
        "Conditional Access and MFA. Microsoft has been disabling them by default "
        "since 2022 but tenants created earlier may still have them on."
    )

    def run(self, client: GraphClient) -> list[Finding]:
        # Read the authentication methods policy
        policy = client.get("policies/authenticationMethodsPolicy")
        legacy_on: list[str] = []
        for method in policy.get("authenticationMethodConfigurations", []):
            mid = method.get("id", "")
            state = method.get("state", "")
            # These methods are considered "legacy" or commonly weak
            if mid in {"Sms", "Voice", "Email"} and state == "enabled":
                legacy_on.append(mid)

        if not legacy_on:
            return []
        return [Finding(
            check_id=self.check_id,
            title="Weak/legacy authentication methods enabled",
            severity=Severity.HIGH,
            description=(
                f"The following authentication methods are enabled tenant-wide "
                f"and are considered weak: {', '.join(legacy_on)}. SMS and voice "
                "MFA are vulnerable to SIM-swap attacks. Email-based MFA is "
                "vulnerable to mailbox compromise."
            ),
            impact="Attackers who phish or SIM-swap a user can complete MFA and access the tenant.",
            recommendation=(
                "In Entra ID > Security > Authentication methods, disable SMS, "
                "Voice, and Email. Require Microsoft Authenticator (push or "
                "passwordless) or FIDO2 keys. Plan a 30-day migration."
            ),
            evidence={"enabled_weak_methods": legacy_on},
            references=[REF_CIS, REF_GRAPH_AUTH],
        )]


@register
class GlobalAdminCountCheck(Check):
    check_id = "ID-002"
    name = "Global Admin role assignment hygiene"
    category = "Identity"
    description = "Microsoft recommends 2-4 Global Administrators per tenant."

    def run(self, client: GraphClient) -> list[Finding]:
        # Find the Global Administrator role
        role_resp = client.get(
            "directoryRoles",
            params={"$filter": "displayName eq 'Global Administrator'"},
        )
        roles = role_resp.get("value", [])
        if not roles:
            return []
        role_id = roles[0]["id"]

        members = list(client.get_all(f"directoryRoles/{role_id}/members"))
        count = len(members)
        emails = [m.get("userPrincipalName") or m.get("displayName") or m.get("id") for m in members]

        findings: list[Finding] = []
        if count < 2:
            findings.append(Finding(
                check_id=self.check_id,
                title="Fewer than 2 Global Administrators (lockout risk)",
                severity=Severity.MEDIUM,
                description=f"Only {count} Global Admin(s) exist. If the sole admin loses access, the tenant becomes unrecoverable without Microsoft support intervention.",
                impact="Operational risk: total tenant lockout if the single admin's account is compromised, lost, or offboarded.",
                recommendation="Designate a second emergency-access (break-glass) Global Admin account with a long random password stored in a sealed envelope or password vault.",
                evidence={"current_count": count, "members": emails},
                references=[REF_CIS, "Microsoft Entra emergency access accounts"],
            ))
        elif count > 4:
            findings.append(Finding(
                check_id=self.check_id,
                title=f"{count} Global Administrators (excessive privilege)",
                severity=Severity.HIGH,
                description=f"{count} accounts hold Global Administrator. Each is a top-tier compromise target.",
                impact="Each Global Admin is a single point of compromise for the entire tenant. More accounts = larger attack surface.",
                recommendation="Reduce to 2-4. Move other admins to least-privilege roles (User Admin, Exchange Admin, etc.). Use Privileged Identity Management (PIM) for just-in-time elevation.",
                evidence={"current_count": count, "members": emails},
                references=[REF_CIS],
                affected_objects=emails,
            ))
        return findings


@register
class GuestUserSettingsCheck(Check):
    check_id = "ID-003"
    name = "Guest user invitation and access policy"
    category = "Identity"
    description = "Verifies guest invitation is restricted to admins or specific roles."

    def run(self, client: GraphClient) -> list[Finding]:
        policy = client.get("policies/authorizationPolicy")
        # allowInvitesFrom values: none, adminsAndGuestInviters, adminsGuestInvitersAndAllMembers, everyone
        allow = policy.get("allowInvitesFrom", "everyone")
        guest_role = policy.get("guestUserRoleId", "")

        findings: list[Finding] = []
        if allow == "everyone":
            findings.append(Finding(
                check_id=self.check_id,
                title="Any user can invite external guests",
                severity=Severity.MEDIUM,
                description="Every member of the tenant can invite external users. This is the M365 default but is rarely the right policy for any org with sensitive data.",
                impact="A compromised or careless internal account can invite an attacker as a guest, granting access to Teams, SharePoint, and shared resources.",
                recommendation="In Entra ID > External Identities > External collaboration settings, set 'Guest invite restrictions' to 'Only users assigned to specific admin roles can invite guest users'.",
                evidence={"allowInvitesFrom": allow},
                references=[REF_CIS],
            ))

        # 10dae51f-b6af-4016-8d66-8c2a99b929b3 is "Guest user (limited)", a90dca5b-... is "User"-equivalent.
        # If guest_role matches the same id as a regular member, that's a hardening gap.
        if guest_role and guest_role.lower() == "a0b1b346-4d3e-4e8b-98f8-753987be4970":  # User role id
            findings.append(Finding(
                check_id=self.check_id,
                title="Guest users have same permissions as members",
                severity=Severity.HIGH,
                description="The tenant grants guests the same directory permissions as regular members. Guests can enumerate users, groups, and apps.",
                impact="Guests can perform reconnaissance to plan further attacks against the tenant.",
                recommendation="Set 'Guest user access restrictions' to 'Guest users have limited access to properties and memberships of directory objects'.",
                evidence={"guestUserRoleId": guest_role},
                references=[REF_CIS],
            ))
        return findings


@register
class StaleAdminAccountsCheck(Check):
    check_id = "ID-004"
    name = "Stale or never-signed-in admin accounts"
    category = "Identity"
    description = "Identifies privileged accounts that haven't signed in recently."

    def run(self, client: GraphClient) -> list[Finding]:
        from datetime import datetime, timedelta, timezone

        # Pull all directory role assignments and check sign-in activity
        role_resp = client.get("directoryRoles")
        privileged_role_names = {
            "Global Administrator", "Privileged Role Administrator",
            "Security Administrator", "Exchange Administrator",
            "SharePoint Administrator", "User Administrator",
        }

        stale: list[dict] = []
        threshold = datetime.now(timezone.utc) - timedelta(days=90)

        for role in role_resp.get("value", []):
            if role.get("displayName") not in privileged_role_names:
                continue
            for member in client.get_all(f"directoryRoles/{role['id']}/members"):
                upn = member.get("userPrincipalName")
                if not upn:
                    continue
                # Get sign-in activity
                try:
                    user = client.get(
                        f"users/{member['id']}",
                        params={"$select": "userPrincipalName,signInActivity,accountEnabled"},
                    )
                except Exception:
                    continue
                sia = user.get("signInActivity") or {}
                last = sia.get("lastSignInDateTime")
                if last:
                    last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                    if last_dt < threshold:
                        stale.append({
                            "upn": upn,
                            "role": role["displayName"],
                            "last_sign_in": last,
                            "days_inactive": (datetime.now(timezone.utc) - last_dt).days,
                        })
                else:
                    stale.append({"upn": upn, "role": role["displayName"], "last_sign_in": "never"})

        if not stale:
            return []
        return [Finding(
            check_id=self.check_id,
            title=f"{len(stale)} privileged account(s) inactive for 90+ days",
            severity=Severity.HIGH,
            description="Privileged accounts that haven't been used in 90 days are likely orphaned. They are prime targets for password-spray attacks since password rotation may have lapsed.",
            impact="Orphaned admin credentials are one of the most common initial-access vectors in M365 breaches.",
            recommendation="Review each account. If the user has left, remove the role assignment. If the account is for emergency access only, document it and ensure the credential is securely stored.",
            evidence={"stale_admins": stale},
            references=[REF_CIS],
            affected_objects=[s["upn"] for s in stale],
        )]
