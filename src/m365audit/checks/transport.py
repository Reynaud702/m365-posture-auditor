"""Exchange Online mail transport rule checks."""
from __future__ import annotations
from ..graph import GraphClient, GraphError
from ..models import Finding, Severity
from .base import Check, register

def _score_check(client, keywords, check_id, title, severity, description, impact, recommendation, references):
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
        if any(k in cid for k in keywords):
            if control.get("score", 0) > 0:
                return []
            return [Finding(check_id=check_id, title=title, severity=severity,
                description=description, impact=impact, recommendation=recommendation,
                evidence={"controls_checked": len(controls)}, references=references)]
    return []

@register
class ExternalAutoForwardCheck(Check):
    check_id = "TR-001"
    name = "External email auto-forwarding policy"
    category = "Mail Transport"
    description = "Checks whether the tenant blocks auto-forwarding to external addresses."
    def run(self, client):
        return _score_check(client, ["autoforward", "externalforward"], "TR-001",
            "External email auto-forwarding may not be blocked", Severity.HIGH,
            "The tenant may not block automatic forwarding to external addresses.",
            "A compromised mailbox can silently forward all email to an attacker.",
            "In Exchange admin center > Mail flow > Remote domains, set auto-forwarding to Off.",
            ["CIS M365 Benchmark 2.1.2"])

@register
class TransportRuleSpamBypassCheck(Check):
    check_id = "TR-002"
    name = "Transport rules that bypass spam filtering"
    category = "Mail Transport"
    description = "Checks for rules that set SCL=-1, bypassing spam and malware filtering."
    def run(self, client):
        return _score_check(client, ["transportrule", "mailflowrule", "sclbypass"], "TR-002",
            "Transport rules may be bypassing spam and malware filtering", Severity.HIGH,
            "Mail flow rules may be skipping all spam and malware filtering.",
            "Phishing and malware land directly in inboxes without scanning.",
            "In Exchange admin center > Mail flow > Rules, audit rules that set SCL to -1.",
            ["CIS M365 Benchmark 2.1.7"])

@register
class TransportRuleSenderWhitelistCheck(Check):
    check_id = "TR-003"
    name = "Transport rules whitelisting external senders"
    category = "Mail Transport"
    description = "Checks for sender whitelists that bypass anti-spoofing controls."
    def run(self, client):
        return _score_check(client, ["allowedsender", "senderwhitelist", "safesender"], "TR-003",
            "External sender whitelists may undermine anti-spoofing controls", Severity.MEDIUM,
            "Allowed sender lists may unconditionally trust external addresses.",
            "Attackers can spoof whitelisted addresses to bypass spam filtering.",
            "Audit anti-spam allow lists and remove broad domain entries.",
            ["CIS M365 Benchmark 2.1.8"])
