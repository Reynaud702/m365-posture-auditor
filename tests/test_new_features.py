"""Tests for Defender checks, multi-tenant mode, and delta/trending mode."""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from m365audit.checks.defender import (
    AntiPhishingPolicyCheck,
    SafeAttachmentsPolicyCheck,
    SafeLinksPolicyCheck,
)
from m365audit.delta import (
    AuditDelta,
    FindingDelta,
    compute_delta,
    render_delta_markdown,
    _finding_key,
)
from m365audit.graph import GraphClient, GraphError
from m365audit.models import (
    AuditReport,
    CheckResult,
    Finding,
    Severity,
    Status,
    make_report,
)
from m365audit.multi_tenant import (
    MultiTenantResult,
    TenantConfig,
    audit_tenant,
    render_multi_summary_json,
    render_multi_summary_markdown,
    run_multi_tenant_audit,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers shared across tests
# ──────────────────────────────────────────────────────────────────────────────

class FakeResponse:
    def __init__(self, status: int, json_data: dict | None = None, text: str = ""):
        self.status_code = status
        self._json = json_data or {}
        self.text = text or ""
        self.headers: dict = {}

    def json(self) -> dict:
        return self._json


class FakeSession:
    def __init__(self):
        self.get_responses: dict[str, FakeResponse] = {}
        self.post_response = FakeResponse(
            200, {"access_token": "fake-token", "expires_in": 3600}
        )

    def get(self, url, headers=None, params=None, timeout=None):
        if url in self.get_responses:
            return self.get_responses[url]
        candidates = [(p, r) for p, r in self.get_responses.items() if url.startswith(p)]
        if candidates:
            candidates.sort(key=lambda kv: -len(kv[0]))
            return candidates[0][1]
        return FakeResponse(404, text="not configured")

    def post(self, url, data=None, timeout=None):
        return self.post_response


def make_client(responses: dict[str, FakeResponse] | None = None) -> GraphClient:
    session = FakeSession()
    if responses:
        session.get_responses.update(responses)
    return GraphClient("tid", "cid", "secret", session=session)


def _sample_finding(
    check_id: str = "ID-001",
    title: str = "Test finding",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        description="desc",
        impact="impact",
        recommendation="rec",
        affected_objects=["user@acme.com"],
    )


def _sample_report(
    findings: list[Finding] | None = None,
    tenant_name: str = "Acme Corp",
) -> AuditReport:
    report = make_report("tid-123", tenant_name)
    if findings:
        from m365audit.models import CheckResult, Status
        for f in findings:
            report.results.append(CheckResult(
                check_id=f.check_id,
                name="test",
                category="test",
                status=Status.FAIL,
                findings=[f],
            ))
    return report


# ──────────────────────────────────────────────────────────────────────────────
# Defender checks
# ──────────────────────────────────────────────────────────────────────────────

class TestDefenderChecks:
    """Defender for Office 365 checks are fail-safe when the tenant lacks the license."""

    def test_antiphishing_skips_when_no_defender_license(self):
        client = make_client({
            "https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts": FakeResponse(
                403, text='{"error": "Access denied"}'
            ),
        })
        check = AntiPhishingPolicyCheck()
        result = check.execute(client)
        assert result.status == Status.PASS
        assert result.findings == []

    def test_antiphishing_skips_on_404(self):
        client = make_client({
            "https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts": FakeResponse(
                404, text='{"error": "Not found"}'
            ),
        })
        check = AntiPhishingPolicyCheck()
        result = check.execute(client)
        assert result.status == Status.PASS
        assert result.findings == []

    def test_antiphishing_flags_when_impersonation_not_in_secure_score(self):
        session = FakeSession()
        # Defender available
        session.get_responses["https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts"] = \
            FakeResponse(200, {"value": []})
        # simulationAutomations succeeds
        session.get_responses["https://graph.microsoft.com/v1.0/security/attackSimulation/simulationAutomations"] = \
            FakeResponse(200, {"value": []})
        # Secure Score with no impersonation control scoring points
        session.get_responses["https://graph.microsoft.com/v1.0/security/secureScores"] = \
            FakeResponse(200, {
                "controlScores": [
                    {"controlName": "SomeOtherControl", "score": 5},
                    {"controlName": "ImpersonationProtection", "score": 0},
                ]
            })
        client = GraphClient("tid", "cid", "secret", session=session)
        check = AntiPhishingPolicyCheck()
        result = check.execute(client)
        assert result.status == Status.FAIL
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_antiphishing_passes_when_impersonation_scoring(self):
        session = FakeSession()
        session.get_responses["https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts"] = \
            FakeResponse(200, {"value": []})
        session.get_responses["https://graph.microsoft.com/v1.0/security/attackSimulation/simulationAutomations"] = \
            FakeResponse(200, {"value": []})
        session.get_responses["https://graph.microsoft.com/v1.0/security/secureScores"] = \
            FakeResponse(200, {
                "controlScores": [
                    {"controlName": "ImpersonationProtection", "score": 8},
                ]
            })
        client = GraphClient("tid", "cid", "secret", session=session)
        check = AntiPhishingPolicyCheck()
        result = check.execute(client)
        assert result.status == Status.PASS

    def test_safe_attachments_skips_when_no_secure_score(self):
        client = make_client({
            "https://graph.microsoft.com/v1.0/security/secureScores": FakeResponse(
                403, text='{"error": "No license"}'
            ),
        })
        check = SafeAttachmentsPolicyCheck()
        result = check.execute(client)
        assert result.status == Status.PASS

    def test_safe_attachments_flags_when_control_present_but_zero(self):
        client = make_client({
            "https://graph.microsoft.com/v1.0/security/secureScores": FakeResponse(
                200, {
                    "controlScores": [
                        {"controlName": "SafeAttachmentsEnabled", "score": 0},
                    ]
                }
            ),
        })
        check = SafeAttachmentsPolicyCheck()
        result = check.execute(client)
        assert result.status == Status.FAIL
        assert result.findings[0].severity == Severity.HIGH

    def test_safe_attachments_passes_when_enabled(self):
        client = make_client({
            "https://graph.microsoft.com/v1.0/security/secureScores": FakeResponse(
                200, {
                    "controlScores": [
                        {"controlName": "SafeAttachmentsEnabled", "score": 5},
                    ]
                }
            ),
        })
        check = SafeAttachmentsPolicyCheck()
        result = check.execute(client)
        assert result.status == Status.PASS

    def test_safe_links_flags_when_control_zero(self):
        client = make_client({
            "https://graph.microsoft.com/v1.0/security/secureScores": FakeResponse(
                200, {
                    "controlScores": [
                        {"controlName": "SafeLinksEnabled", "score": 0},
                    ]
                }
            ),
        })
        check = SafeLinksPolicyCheck()
        result = check.execute(client)
        assert result.status == Status.FAIL

    def test_safe_links_passes_when_enabled(self):
        client = make_client({
            "https://graph.microsoft.com/v1.0/security/secureScores": FakeResponse(
                200, {
                    "controlScores": [
                        {"controlName": "SafeLinksEnabled", "score": 3},
                    ]
                }
            ),
        })
        check = SafeLinksPolicyCheck()
        result = check.execute(client)
        assert result.status == Status.PASS

    def test_defender_checks_registered(self):
        from m365audit.checks.base import _REGISTRY
        names = {cls.__name__ for cls in _REGISTRY}
        assert "AntiPhishingPolicyCheck" in names
        assert "SafeAttachmentsPolicyCheck" in names
        assert "SafeLinksPolicyCheck" in names


# ──────────────────────────────────────────────────────────────────────────────
# Multi-tenant
# ──────────────────────────────────────────────────────────────────────────────

class TestMultiTenant:
    def _make_config(self, name: str = "Acme", alias: str = "acme") -> TenantConfig:
        return TenantConfig(
            tenant_id="tid-1",
            client_id="cid-1",
            client_secret="secret",
            tenant_name=name,
            alias=alias,
        )

    def test_tenant_config_derives_alias(self):
        cfg = TenantConfig("tid", "cid", "s", "Acme Corp")
        assert cfg.alias == "acme-corp"

    def test_tenant_config_alias_sanitized(self):
        cfg = TenantConfig("tid", "cid", "s", "Acme / Corp Inc.")
        assert "/" not in cfg.alias

    def test_load_tenant_configs_from_json(self, tmp_path):
        from m365audit.multi_tenant import load_tenant_configs
        data = [
            {
                "tenant_id": "tid-1",
                "client_id": "cid-1",
                "client_secret": "secret1",
                "tenant_name": "Acme Corp",
                "alias": "acme",
            },
            {
                "tenant_id": "tid-2",
                "client_id": "cid-2",
                "client_secret": "secret2",
                "tenant_name": "Beta Inc",
            },
        ]
        p = tmp_path / "tenants.json"
        p.write_text(json.dumps(data))
        configs = load_tenant_configs(p)
        assert len(configs) == 2
        assert configs[0].alias == "acme"
        assert configs[1].tenant_name == "Beta Inc"
        assert configs[1].alias  # auto-derived

    def test_audit_tenant_returns_result_on_success(self):
        cfg = self._make_config()
        with patch("m365audit.multi_tenant.run_audit") as mock_run, \
             patch("m365audit.multi_tenant.GraphClient"):
            mock_run.return_value = _sample_report()
            result = audit_tenant(cfg)
        assert result.success
        assert result.error is None
        assert result.report is not None

    def test_audit_tenant_captures_error(self):
        cfg = self._make_config()
        with patch("m365audit.multi_tenant.GraphClient") as MockClient:
            MockClient.side_effect = Exception("connection refused")
            result = audit_tenant(cfg)
        assert not result.success
        assert "connection refused" in (result.error or "")

    def test_run_multi_tenant_audit_returns_all_results(self):
        configs = [
            self._make_config("Acme", "acme"),
            self._make_config("Beta", "beta"),
        ]
        configs[1].tenant_id = "tid-2"

        with patch("m365audit.multi_tenant.audit_tenant") as mock_audit:
            def side_effect(cfg, auditor=None, only=None):
                return MultiTenantResult(config=cfg, report=_sample_report(tenant_name=cfg.tenant_name))
            mock_audit.side_effect = side_effect
            results = run_multi_tenant_audit(configs, max_workers=2)

        assert len(results) == 2

    def test_render_multi_summary_json(self):
        cfg = self._make_config()
        report = _sample_report(findings=[_sample_finding()])
        results = [MultiTenantResult(config=cfg, report=report)]
        summary = render_multi_summary_json(results)
        assert summary["tenant_count"] == 1
        assert summary["successful"] == 1
        assert summary["failed"] == 0
        assert summary["tenants"][0]["posture_grade"] == report.posture_grade

    def test_render_multi_summary_json_includes_failures(self):
        cfg = self._make_config()
        results = [MultiTenantResult(config=cfg, error="timeout")]
        summary = render_multi_summary_json(results)
        assert summary["failed"] == 1
        assert "error" in summary["tenants"][0]

    def test_render_multi_summary_markdown(self):
        cfg = self._make_config()
        report = _sample_report(findings=[_sample_finding(severity=Severity.CRITICAL)])
        results = [MultiTenantResult(config=cfg, report=report)]
        md = render_multi_summary_markdown(results)
        assert "Acme" in md
        assert "Critical" in md

    def test_write_multi_tenant_reports(self, tmp_path):
        from m365audit.multi_tenant import write_multi_tenant_reports
        cfg = self._make_config()
        report = _sample_report()
        results = [MultiTenantResult(config=cfg, report=report)]
        write_multi_tenant_reports(results, output_dir=tmp_path, no_pdf=True)
        assert (tmp_path / "acme.json").exists()
        assert (tmp_path / "acme.md").exists()
        assert (tmp_path / "multi-tenant-summary.json").exists()
        assert (tmp_path / "multi-tenant-summary.md").exists()


# ──────────────────────────────────────────────────────────────────────────────
# Delta / trending
# ──────────────────────────────────────────────────────────────────────────────

class TestDelta:
    def _make_baseline_json(self, findings: list[Finding], tmp_path: Path) -> Path:
        """Create a fake previous-audit JSON file."""
        report = _sample_report(findings=findings)
        data = report.to_dict()
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps(data, default=str))
        return p

    def test_finding_key_is_stable(self):
        f1 = _sample_finding("ID-001", "Too many Global Admins", Severity.HIGH)
        f2 = _sample_finding("ID-001", "Too many Global Admins!", Severity.HIGH)
        # Should be same key (punctuation stripped)
        assert _finding_key(f1) == _finding_key(f2)

    def test_finding_key_differs_by_check_id(self):
        f1 = _sample_finding("ID-001", "same title")
        f2 = _sample_finding("ID-002", "same title")
        assert _finding_key(f1) != _finding_key(f2)

    def test_finding_key_differs_by_severity(self):
        f1 = _sample_finding("ID-001", "same title", Severity.HIGH)
        f2 = _sample_finding("ID-001", "same title", Severity.CRITICAL)
        assert _finding_key(f1) != _finding_key(f2)

    def test_compute_delta_new_finding(self, tmp_path):
        baseline_path = self._make_baseline_json([], tmp_path)
        current = _sample_report(findings=[_sample_finding("ID-001", "New Issue")])
        delta = compute_delta(current, baseline_path)
        assert len(delta.new_findings) == 1
        assert len(delta.resolved_findings) == 0
        assert delta.new_findings[0].check_id == "ID-001"

    def test_compute_delta_resolved_finding(self, tmp_path):
        baseline_path = self._make_baseline_json(
            [_sample_finding("CA-001", "No MFA Policy")], tmp_path
        )
        current = _sample_report(findings=[])
        delta = compute_delta(current, baseline_path)
        assert len(delta.resolved_findings) == 1
        assert len(delta.new_findings) == 0

    def test_compute_delta_persisting_finding(self, tmp_path):
        finding = _sample_finding("ID-002", "Too many Global Admins")
        baseline_path = self._make_baseline_json([finding], tmp_path)
        current = _sample_report(findings=[finding])
        delta = compute_delta(current, baseline_path)
        assert len(delta.persisting_findings) == 1
        assert len(delta.new_findings) == 0
        assert len(delta.resolved_findings) == 0

    def test_compute_delta_score_change(self, tmp_path):
        baseline_path = self._make_baseline_json(
            [_sample_finding("ID-001", "A", Severity.CRITICAL)], tmp_path
        )
        current = _sample_report(findings=[])
        delta = compute_delta(current, baseline_path)
        assert delta.score_change < 0  # improved
        assert delta.improved

    def test_compute_delta_score_worsened(self, tmp_path):
        baseline_path = self._make_baseline_json([], tmp_path)
        current = _sample_report(findings=[
            _sample_finding("ID-001", "New critical", Severity.CRITICAL),
            _sample_finding("ID-002", "New high", Severity.HIGH),
        ])
        delta = compute_delta(current, baseline_path)
        assert delta.score_change > 0
        assert not delta.improved

    def test_render_delta_markdown_new_section(self, tmp_path):
        baseline_path = self._make_baseline_json([], tmp_path)
        current = _sample_report(findings=[_sample_finding("ID-001", "Brand new issue")])
        delta = compute_delta(current, baseline_path)
        md = render_delta_markdown(delta)
        assert "New Findings" in md
        assert "Brand new issue" in md

    def test_render_delta_markdown_resolved_section(self, tmp_path):
        baseline_path = self._make_baseline_json(
            [_sample_finding("CA-001", "Old issue fixed")], tmp_path
        )
        current = _sample_report(findings=[])
        delta = compute_delta(current, baseline_path)
        md = render_delta_markdown(delta)
        assert "Resolved" in md
        assert "Old issue fixed" in md

    def test_render_delta_markdown_no_change(self, tmp_path):
        finding = _sample_finding("EM-001", "Forwarding rules")
        baseline_path = self._make_baseline_json([finding], tmp_path)
        current = _sample_report(findings=[finding])
        delta = compute_delta(current, baseline_path)
        md = render_delta_markdown(delta)
        assert "Persisting" in md
        assert "Forwarding rules" in md

    def test_delta_to_dict_round_trips(self, tmp_path):
        baseline_path = self._make_baseline_json(
            [_sample_finding("ID-001", "Stale admins")], tmp_path
        )
        current = _sample_report(findings=[
            _sample_finding("ID-001", "Stale admins"),  # persisting
            _sample_finding("CA-001", "No MFA"),        # new
        ])
        delta = compute_delta(current, baseline_path)
        d = delta.to_dict()
        assert d["new_findings_count"] == 1
        assert d["resolved_findings_count"] == 0
        assert d["persisting_findings_count"] == 1
        assert isinstance(d["score_change"], int)
