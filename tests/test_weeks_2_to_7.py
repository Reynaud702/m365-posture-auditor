"""Basic tests for weeks 2-7 features."""
from __future__ import annotations
from unittest.mock import MagicMock
from m365audit.checks.teams import TeamsExternalAccessCheck, TeamsGuestAccessCheck, TeamsMeetingAnonymousJoinCheck
from m365audit.checks.transport import ExternalAutoForwardCheck, TransportRuleSpamBypassCheck, TransportRuleSenderWhitelistCheck
from m365audit.models import AuditReport, CheckResult, Finding, Severity, Status, make_report
from m365audit.report_html import render_html
from m365audit.thresholds import ThresholdConfig, apply_thresholds, default_config
from m365audit.csf_mapping import get_controls, csf_summary, render_csf_appendix
import tempfile, json
from datetime import datetime, timezone
from m365audit.history import SnapshotStore

def _client(responses):
    client = MagicMock()
    def _get(path, **kwargs):
        for key, val in responses.items():
            if path.startswith(key):
                if isinstance(val, Exception): raise val
                return val
        return {}
    client.get.side_effect = _get
    return client

def _report(check_id="ID-001", severity=Severity.HIGH):
    report = make_report("t1", "Test Tenant")
    f = Finding(check_id=check_id, title="Test", severity=severity, description="d", impact="i", recommendation="r")
    report.results.append(CheckResult(check_id=check_id, name="Test", category="Cat", status=Status.FAIL, findings=[f]))
    return report

# Teams checks
def test_tm001_skips_when_no_settings():
    from m365audit.graph import GraphError
    c = _client({"teamwork": GraphError(403,"Forbidden","/t"), "security/secureScores": {"controlScores":[]}})
    assert TeamsExternalAccessCheck().run(c) == []

def test_tm001_flags_when_not_restricted():
    c = _client({"teamwork": {"ok":True}, "security/secureScores": {"controlScores":[{"controlName":"TeamsExternalAccess","score":0}]}})
    findings = TeamsExternalAccessCheck().run(c)
    assert len(findings) == 1 and findings[0].check_id == "TM-001"

def test_tm001_passes_when_controlled():
    c = _client({"teamwork": {"ok":True}, "security/secureScores": {"controlScores":[{"controlName":"TeamsExternalAccess","score":5}]}})
    assert TeamsExternalAccessCheck().run(c) == []

def test_tm002_skips_on_403():
    from m365audit.graph import GraphError
    c = _client({"groupSettings": GraphError(403,"Forbidden","/g")})
    assert TeamsGuestAccessCheck().run(c) == []

def test_tm002_flags_owner_permission():
    c = _client({"groupSettings": {"value":[{"values":[{"name":"AllowGuestsToBeGroupOwner","value":"true"}]}]}})
    findings = TeamsGuestAccessCheck().run(c)
    assert len(findings) == 1 and findings[0].severity == Severity.HIGH

def test_tm002_passes_when_owner_disabled():
    c = _client({"groupSettings": {"value":[{"values":[{"name":"AllowGuestsToBeGroupOwner","value":"false"}]}]}})
    assert TeamsGuestAccessCheck().run(c) == []

def test_tm003_skips_no_controls():
    c = _client({"security/secureScores": {"controlScores":[]}})
    assert TeamsMeetingAnonymousJoinCheck().run(c) == []

def test_tm003_flags_when_not_blocked():
    c = _client({"security/secureScores": {"controlScores":[{"controlName":"AnonymousMeetingJoin","score":0}]}})
    findings = TeamsMeetingAnonymousJoinCheck().run(c)
    assert len(findings) == 1 and findings[0].check_id == "TM-003"

def test_teams_checks_registered():
    from m365audit.checks import all_checks
    ids = {c.check_id for c in all_checks()}
    assert "TM-001" in ids and "TM-002" in ids and "TM-003" in ids

# Transport checks
def test_tr001_skips_no_controls():
    c = _client({"security/secureScores": {"controlScores":[]}})
    assert ExternalAutoForwardCheck().run(c) == []

def test_tr001_flags_when_not_blocked():
    c = _client({"security/secureScores": {"controlScores":[{"controlName":"AutoForwardEnabled","score":0}]}})
    findings = ExternalAutoForwardCheck().run(c)
    assert len(findings) == 1 and findings[0].check_id == "TR-001"

def test_tr002_flags_when_not_controlled():
    c = _client({"security/secureScores": {"controlScores":[{"controlName":"MailFlowRuleBypass","score":0}]}})
    findings = TransportRuleSpamBypassCheck().run(c)
    assert len(findings) == 1 and findings[0].check_id == "TR-002"

def test_tr003_flags_when_present():
    c = _client({"security/secureScores": {"controlScores":[{"controlName":"AllowedSenderList","score":0}]}})
    findings = TransportRuleSenderWhitelistCheck().run(c)
    assert len(findings) == 1 and findings[0].check_id == "TR-003"

def test_transport_checks_registered():
    from m365audit.checks import all_checks
    ids = {c.check_id for c in all_checks()}
    assert "TR-001" in ids and "TR-002" in ids and "TR-003" in ids

# HTML report
def test_html_renders():
    html = render_html(_report())
    assert html.startswith("<!DOCTYPE html>") and "</html>" in html

def test_html_includes_tenant_name():
    report = make_report("t1", "Acme School District")
    assert "Acme School District" in render_html(report)

def test_html_no_findings_message():
    assert "No findings" in render_html(make_report("t1", "Clean Tenant"))

def test_html_includes_finding_title():
    assert "Test" in render_html(_report())

# Thresholds
def test_default_config_passes_all():
    config = default_config()
    for sev in Severity:
        assert config.meets_minimum_severity(sev)

def test_minimum_severity_filters_low():
    config = ThresholdConfig(minimum_severity="Medium")
    assert config.meets_minimum_severity(Severity.HIGH)
    assert not config.meets_minimum_severity(Severity.LOW)

def test_suppressed_check_excluded():
    config = ThresholdConfig(suppressed_checks=["ID-001"])
    assert config.is_suppressed("ID-001")
    assert not config.is_suppressed("ID-002")

def test_severity_override_applied():
    config = ThresholdConfig(severity_overrides={"TR-003": "High"})
    f = Finding(check_id="TR-003", title="t", severity=Severity.MEDIUM, description="d", impact="i", recommendation="r")
    assert config.apply_override(f).severity == Severity.HIGH

def test_apply_thresholds_removes_suppressed():
    report = _report(check_id="ID-001")
    filtered = apply_thresholds(report, ThresholdConfig(suppressed_checks=["ID-001"]))
    assert not any(r.check_id == "ID-001" for r in filtered.results)

def test_grade_fails_when_worse():
    config = ThresholdConfig(fail_on_grade="B")
    assert config.grade_fails("C") and not config.grade_fails("A")

# Snapshot history
def test_snapshot_save_and_list():
    with tempfile.TemporaryDirectory() as tmp:
        store = SnapshotStore(tmp)
        report = make_report("tenant-abc", "Test Org")
        path = store.save(report)
        assert path.exists()
        snapshots = store.list_snapshots("tenant-abc")
        assert len(snapshots) == 1

def test_latest_baseline_none_when_one_snapshot():
    with tempfile.TemporaryDirectory() as tmp:
        store = SnapshotStore(tmp)
        store.save(make_report("t1", "Test"))
        assert store.latest_baseline("t1") is None

def test_latest_baseline_returns_previous():
    with tempfile.TemporaryDirectory() as tmp:
        store = SnapshotStore(tmp)
        r1 = make_report("t1", "Test")
        r1.generated_at = datetime(2026,1,1,tzinfo=timezone.utc)
        r2 = make_report("t1", "Test")
        r2.generated_at = datetime(2026,2,1,tzinfo=timezone.utc)
        store.save(r1)
        store.save(r2)
        assert store.latest_baseline("t1") is not None

def test_prune_removes_oldest():
    with tempfile.TemporaryDirectory() as tmp:
        store = SnapshotStore(tmp)
        for i in range(5):
            r = make_report("t-prune", "Test")
            r.generated_at = datetime(2026,i+1,1,tzinfo=timezone.utc)
            store.save(r)
        store.prune("t-prune", keep=3)
        assert len(store.list_snapshots("t-prune")) == 3

def test_trend_markdown_renders():
    with tempfile.TemporaryDirectory() as tmp:
        store = SnapshotStore(tmp)
        store.save(make_report("t1", "Test Org"))
        assert "Posture Trend" in store.trend_markdown("t1")

def test_trend_markdown_no_snapshots():
    with tempfile.TemporaryDirectory() as tmp:
        store = SnapshotStore(tmp)
        assert "No snapshots" in store.trend_markdown("nobody")

# CSF mapping
def test_get_controls_known_check():
    assert len(get_controls("TM-001")) > 0

def test_get_controls_unknown_check():
    assert get_controls("XX-999") == []

def test_new_checks_have_mappings():
    for cid in ["TM-001","TM-002","TM-003","TR-001","TR-002","TR-003"]:
        assert len(get_controls(cid)) > 0

def test_csf_summary_counts():
    summary = csf_summary(["TM-001","TR-001"])
    assert summary["total_subcategories_covered"] > 0

def test_render_csf_appendix_includes_ids():
    appendix = render_csf_appendix(["TM-001","TR-001"])
    assert "TM-001" in appendix and "TR-001" in appendix

def test_render_csf_appendix_no_checks():
    assert "No mapped checks found" in render_csf_appendix([])
