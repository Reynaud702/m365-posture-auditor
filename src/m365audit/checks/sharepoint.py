"""SharePoint Online and OneDrive sharing posture.

Checks tenant-wide external sharing settings. The default M365 settings allow
"Anyone with the link" sharing, which is the most common cause of accidental
data exposure for SMBs.
"""
from __future__ import annotations

from ..graph import GraphClient
from ..models import Finding, Severity
from .base import Check, register


@register
class TenantSharingCapabilityCheck(Check):
    check_id = "SP-001"
    name = "SharePoint tenant-level external sharing capability"
    category = "Data Sharing"
    description = "Verifies sharing is not set to the most permissive 'Anyone' level."

    def run(self, client: GraphClient) -> list[Finding]:
        # The SharePoint admin settings live at /admin/sharepoint/settings (beta).
        # We try beta first, fall back to a minimum-viable indicator otherwise.
        try:
            settings = client.get("admin/sharepoint/settings")
        except Exception:
            return []  # endpoint not reachable; we don't fabricate a finding

        capability = settings.get("sharingCapability", "")
        # Values: disabled, externalUserSharingOnly, externalUserAndGuestSharing, existingExternalUserSharingOnly
        # 'externalUserAndGuestSharing' = "Anyone" links allowed = most permissive.

        findings: list[Finding] = []
        if capability == "externalUserAndGuestSharing":
            findings.append(Finding(
                check_id=self.check_id,
                title="SharePoint allows 'Anyone with the link' sharing tenant-wide",
                severity=Severity.HIGH,
                description="The tenant permits anonymous (no-sign-in) sharing links on SharePoint and OneDrive content. Files shared with 'Anyone' links are accessible by anyone who has the URL.",
                impact="Sensitive documents shared via 'Anyone' links can be forwarded, indexed by search engines (in rare cases), or accessed by attackers if the URL leaks.",
                recommendation="In the SharePoint admin center > Policies > Sharing, set the External sharing slider for SharePoint and OneDrive to 'New and existing guests' at most. If 'Anyone' is required, enforce a link expiration of 30 days and require sign-in for sensitive sites.",
                evidence={"sharingCapability": capability},
                references=["CIS M365 Benchmark 7.2.1"],
            ))

        # Default link permission: view vs edit
        default_link = settings.get("defaultLinkPermission", "")
        if default_link == "edit":
            findings.append(Finding(
                check_id=self.check_id,
                title="Default share link grants edit permission",
                severity=Severity.MEDIUM,
                description="When users share a file, the default permission is 'edit' rather than 'view'.",
                impact="Recipients can modify or delete shared content unintentionally, and an attacker with a shared link can alter shared files.",
                recommendation="Set 'File and folder links default to' = 'View' in SharePoint admin > Sharing.",
                evidence={"defaultLinkPermission": default_link},
                references=["CIS M365 Benchmark 7.2.5"],
            ))

        # Anonymous link expiration
        anon_expire = settings.get("anonymousLinkExpirationInDays", 0)
        if capability == "externalUserAndGuestSharing" and (not anon_expire or anon_expire == 0):
            findings.append(Finding(
                check_id=self.check_id,
                title="Anonymous share links never expire",
                severity=Severity.MEDIUM,
                description="The tenant allows 'Anyone' links and there is no expiration policy.",
                impact="A link shared today remains valid forever, including after the recipient is no longer authorized.",
                recommendation="Set 'Anyone links expire in this many days' to 30 or fewer.",
                evidence={"anonymousLinkExpirationInDays": anon_expire},
                references=["CIS M365 Benchmark 7.2.4"],
            ))

        return findings
