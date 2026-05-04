"""Tests for data models and report rendering."""
from datetime import datetime, timezone

from m365audit.models import (
    AuditReport,
    CheckResult,
    Finding,
    Severity,
    Status,
    make_report,
)
from m365audit.report_md import render_markdown


def _finding(check_id="X-001", sev=Severity.HIGH):
    return Finding(
        check_id=check_id,
        title="Test finding",
        severity=sev,
        description="A description.",
        impact="Impact.",
        recommendation="Fix it.",
        affected_objects=["alice@example.com", "bob@example.com"],
        references=["https://example.com"],
    )


def test_make_report_initializes_empty():
    r = make_report("tenant-guid", "Acme Corp")
    assert r.tenant_id == "tenant-guid"
    assert r.tenant_name == "Acme Corp"
    assert r.results == []
    assert r.risk_score == 0
    assert r.posture_grade == "A"


def test_risk_score_weights_severity():
    r = make_report("tid", "Acme")
    r.results.append(CheckResult(
        check_id="X-001", name="x", category="c",
        status=Status.FAIL, findings=[_finding(sev=Severity.CRITICAL)],
    ))
    assert r.risk_score == 25
    r.results.append(CheckResult(
        check_id="X-002", name="x2", category="c",
        status=Status.FAIL, findings=[_finding(sev=Severity.HIGH)],
    ))
    assert r.risk_score == 35


def test_risk_score_capped_at_100():
    r = make_report("tid", "Acme")
    for i in range(10):
        r.results.append(CheckResult(
            check_id=f"X-{i:03d}", name="x", category="c",
            status=Status.FAIL, findings=[_finding(sev=Severity.CRITICAL)],
        ))
    assert r.risk_score == 100


def test_posture_grades():
    r = make_report("tid", "Acme")
    assert r.posture_grade == "A"
    r.results.append(CheckResult(
        check_id="X", name="x", category="c", status=Status.FAIL,
        findings=[_finding(sev=Severity.LOW)],
    ))
    # 1 low = 1 point => A-
    assert r.posture_grade == "A-"


def test_findings_grouped_by_severity():
    r = make_report("tid", "Acme")
    r.results.append(CheckResult(
        check_id="X-001", name="x", category="c", status=Status.FAIL,
        findings=[_finding(sev=Severity.CRITICAL), _finding(sev=Severity.MEDIUM)],
    ))
    grouped = r.findings_by_severity
    assert len(grouped["Critical"]) == 1
    assert len(grouped["Medium"]) == 1
    assert len(grouped["High"]) == 0


def test_to_dict_round_trips():
    r = make_report("tid", "Acme")
    r.results.append(CheckResult(
        check_id="X-001", name="x", category="c", status=Status.FAIL,
        findings=[_finding()],
    ))
    d = r.to_dict()
    assert d["tenant_id"] == "tid"
    assert d["summary"]["risk_score"] > 0
    assert d["summary"]["counts"]["High"] == 1
    assert len(d["results"]) == 1


def test_render_markdown_includes_findings():
    r = make_report("tid", "Acme Corp")
    r.results.append(CheckResult(
        check_id="X-001", name="x", category="c", status=Status.FAIL,
        findings=[_finding(check_id="X-001", sev=Severity.CRITICAL)],
    ))
    md = render_markdown(r)
    assert "Microsoft 365 Security Posture Assessment" in md
    assert "Acme Corp" in md
    assert "Critical" in md
    assert "X-001" in md
    assert "alice@example.com" in md


def test_render_markdown_no_findings():
    r = make_report("tid", "Acme Corp")
    r.results.append(CheckResult(
        check_id="X-001", name="x", category="c", status=Status.PASS,
    ))
    md = render_markdown(r)
    assert "No Critical or High severity findings" in md
    assert "Posture Grade: A" in md
