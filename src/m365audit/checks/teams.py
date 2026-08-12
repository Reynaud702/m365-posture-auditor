"""Microsoft Teams security checks."""
from __future__ import annotations
from ..graph import GraphClient, GraphError
from ..models import Finding, Severity
from .base import Check, register

def _get_teams_settings(client, path):
    try:
        return client.get(path)
    except GraphError as e:
        if e.status in (403, 404):
            return None
        raise

@register
class TeamsExternalAccessCheck(Check):
    check_id = "TM-001"
    name = "Teams external access (federation) policy"
    category = "Microsoft Teams"
    description = "Verifies Teams external access is not open to all external domains."

    def run(self, client):
        settings = _get_teams_settings(client, "teamwork/teamsAppSettings")
        if settings is None:
            return []
        try:
            score_resp = client.get("security/secureScores", params={"$top": "1"})
            controls = score_resp.get("controlScores", [])
        except GraphError as e:
            if e.status in (403, 404):
                return []
            raise
        for control in controls:
            cid = (control.get("controlName") or "").lower().replace(" ", "").replace("_", "")
            if "teamsexternal" in cid or "externalaccess" in cid:
                if control.get("score", 0) > 0:
                    return []
                return [Finding(
                    check_id=self.check_id,
                    title="Teams external access may allow all external domains",
                    severity=Severity.MEDIUM,
                    description="Teams federation is not restricted to approved domains.",
                    impact="Any Teams user from any org can message internal users directly.",
                    recommendation="In Teams admin center > External access, restrict to specific domains.",
                    evidence={"secure_score_controls_found": len(controls)},
                    references=["CIS M365 Benchmark 3.1.1"],
                )]
        return []

@register
class TeamsGuestAccessCheck(Check):
    check_id = "TM-002"
    name = "Teams guest access configuration"
    category = "Microsoft Teams"
    description = "Checks whether guests can be group owners in Teams."

    def run(self, client):
        try:
            resp = client.get("groupSettings")
            settings_list = resp.get("value", [])
        except GraphError as e:
            if e.status in (403, 404):
                return []
            raise
        for setting_group in settings_list:
            for val in setting_group.get("values", []):
                if val.get("name") == "AllowGuestsToBeGroupOwner":
                    if str(val.get("value", "")).lower() == "true":
                        return [Finding(
                            check_id=self.check_id,
                            title="Teams guests are permitted to be group owners",
                            severity=Severity.HIGH,
                            description="Guest users can be assigned as group owners in Teams.",
                            impact="Compromised guest accounts can add users and modify Team settings.",
                            recommendation="In Azure AD > External Identities, prevent guests from becoming group owners.",
                            evidence={"setting": "AllowGuestsToBeGroupOwner=true"},
                            references=["CIS M365 Benchmark 3.1.2"],
                        )]
        return []

@register
class TeamsMeetingAnonymousJoinCheck(Check):
    check_id = "TM-003"
    name = "Teams meeting anonymous join policy"
    category = "Microsoft Teams"
    description = "Verifies anonymous users cannot join meetings without lobby admission."

    def run(self, client):
        try:
            score_resp = client.get("security/secureScores", params={"$top": "1"})
            controls = score_resp.get("controlScores", [])
        except GraphError as e:
            if e.status in (403, 404):
                return []
            raise
        if not controls:
            return []
        for control in controls:
            cid = (control.get("controlName") or "").lower().replace(" ", "").replace("_", "")
            if "anonymous" in cid and "meeting" in cid:
                if control.get("score", 0) > 0:
                    return []
                return [Finding(
                    check_id=self.check_id,
                    title="Teams meetings may permit anonymous join",
                    severity=Severity.MEDIUM,
                    description="Anonymous users may join Teams meetings without authenticating.",
                    impact="Anyone with a meeting link can silently join calls.",
                    recommendation="In Teams admin center > Meetings, set anonymous join to Off.",
                    evidence={"secure_score_controls_found": len(controls)},
                    references=["CIS M365 Benchmark 3.2.1"],
                )]
        return []
