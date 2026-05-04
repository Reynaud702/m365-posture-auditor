"""Tests for GraphClient and Check execution.

Uses a fake session that returns canned responses, so no real Graph access
is required. This lets us test the auth flow, pagination, and individual
check logic deterministically.
"""
from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from m365audit.checks.base import Check, _REGISTRY
from m365audit.checks.identity import GlobalAdminCountCheck, LegacyAuthEnabledCheck
from m365audit.graph import GraphClient, GraphError
from m365audit.models import Severity, Status


class FakeResponse:
    def __init__(self, status: int, json_data: dict | None = None, text: str = ""):
        self.status_code = status
        self._json = json_data or {}
        self.text = text or ""
        self.headers: dict[str, str] = {}

    def json(self) -> dict:
        return self._json


class FakeSession:
    def __init__(self):
        self.gets: list[tuple[str, dict | None]] = []
        self.posts: list[tuple[str, dict | None]] = []
        self.get_responses: dict[str, FakeResponse] = {}
        self.post_response: FakeResponse | None = None

    def get(self, url, headers=None, params=None, timeout=None):
        self.gets.append((url, params))
        # Exact match first, then longest-prefix match (so /users?skip=2 matches
        # before /users when both are configured).
        if url in self.get_responses:
            return self.get_responses[url]
        candidates = [(p, r) for p, r in self.get_responses.items() if url.startswith(p)]
        if candidates:
            # pick longest prefix
            candidates.sort(key=lambda kv: -len(kv[0]))
            return candidates[0][1]
        return FakeResponse(404, text="not configured")

    def post(self, url, data=None, timeout=None):
        self.posts.append((url, data))
        return self.post_response or FakeResponse(
            200, {"access_token": "fake-token", "expires_in": 3600}
        )


@pytest.fixture
def fake_client():
    session = FakeSession()
    client = GraphClient("tid", "cid", "secret", session=session)
    return client, session


def test_token_acquisition_and_caching(fake_client):
    client, session = fake_client
    t1 = client._acquire_token()
    assert t1 == "fake-token"
    assert len(session.posts) == 1
    # Second call should use cache, not POST again
    t2 = client._acquire_token()
    assert t2 == "fake-token"
    assert len(session.posts) == 1


def test_token_refresh_when_expired(fake_client):
    client, session = fake_client
    client._acquire_token()
    client._token_expires_at = time.time() - 10  # force expiry
    client._acquire_token()
    assert len(session.posts) == 2


def test_get_returns_json_on_200(fake_client):
    client, session = fake_client
    session.get_responses["https://graph.microsoft.com/v1.0/users"] = FakeResponse(
        200, {"value": [{"id": "1"}]}
    )
    body = client.get("users")
    assert body["value"][0]["id"] == "1"


def test_get_raises_graphError_on_failure(fake_client):
    client, session = fake_client
    session.get_responses["https://graph.microsoft.com/v1.0/users"] = FakeResponse(
        403, text='{"error":"forbidden"}'
    )
    with pytest.raises(GraphError) as exc:
        client.get("users")
    assert exc.value.status == 403


def test_get_all_paginates(fake_client):
    client, session = fake_client
    page1 = FakeResponse(200, {
        "value": [{"id": "1"}, {"id": "2"}],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?skip=2",
    })
    page2 = FakeResponse(200, {"value": [{"id": "3"}]})
    session.get_responses["https://graph.microsoft.com/v1.0/users"] = page1
    session.get_responses["https://graph.microsoft.com/v1.0/users?skip=2"] = page2

    items = list(client.get_all("users"))
    assert [i["id"] for i in items] == ["1", "2", "3"]


def test_legacy_auth_check_finds_weak_methods(fake_client):
    client, session = fake_client
    session.get_responses["https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"] = FakeResponse(
        200,
        {
            "authenticationMethodConfigurations": [
                {"id": "Sms", "state": "enabled"},
                {"id": "Voice", "state": "enabled"},
                {"id": "MicrosoftAuthenticator", "state": "enabled"},
            ]
        },
    )
    check = LegacyAuthEnabledCheck()
    result = check.execute(client)
    assert result.status == Status.FAIL
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert "Sms" in f.evidence["enabled_weak_methods"]
    assert "Voice" in f.evidence["enabled_weak_methods"]


def test_legacy_auth_check_passes_when_clean(fake_client):
    client, session = fake_client
    session.get_responses["https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"] = FakeResponse(
        200,
        {"authenticationMethodConfigurations": [
            {"id": "MicrosoftAuthenticator", "state": "enabled"},
            {"id": "Fido2", "state": "enabled"},
            {"id": "Sms", "state": "disabled"},
        ]},
    )
    check = LegacyAuthEnabledCheck()
    result = check.execute(client)
    assert result.status == Status.PASS
    assert result.findings == []


def test_global_admin_count_flags_too_many(fake_client):
    client, session = fake_client
    # Note: requests passes params separately so the URL the fake sees is the
    # base URL — but the URL prefix matcher will hit it.
    session.get_responses["https://graph.microsoft.com/v1.0/directoryRoles"] = FakeResponse(
        200, {"value": [{"id": "role-1"}]}
    )
    # Members: 6 admins
    session.get_responses["https://graph.microsoft.com/v1.0/directoryRoles/role-1/members"] = FakeResponse(
        200,
        {"value": [{"userPrincipalName": f"admin{i}@acme.com", "id": str(i)} for i in range(6)]},
    )
    check = GlobalAdminCountCheck()
    result = check.execute(client)
    assert result.status == Status.FAIL
    assert result.findings[0].severity == Severity.HIGH
    assert "6 Global Administrators" in result.findings[0].title


def test_global_admin_count_flags_too_few(fake_client):
    client, session = fake_client
    session.get_responses["https://graph.microsoft.com/v1.0/directoryRoles"] = FakeResponse(
        200, {"value": [{"id": "role-1"}]}
    )
    session.get_responses["https://graph.microsoft.com/v1.0/directoryRoles/role-1/members"] = FakeResponse(
        200, {"value": [{"userPrincipalName": "lone@acme.com", "id": "1"}]}
    )
    check = GlobalAdminCountCheck()
    result = check.execute(client)
    assert result.status in (Status.FAIL, Status.WARN)
    assert any("lockout" in f.title.lower() for f in result.findings)


def test_check_handles_graph_error_gracefully(fake_client):
    client, session = fake_client
    # No mock set up means get() will return 404 -> GraphError -> Status.ERROR
    check = LegacyAuthEnabledCheck()
    result = check.execute(client)
    assert result.status == Status.ERROR
    assert "Graph API error" in (result.error_message or "")


def test_registry_is_populated():
    # All checks should be registered via @register decorator
    assert len(_REGISTRY) > 0
    # Sanity: our core identity check is in there
    assert any(cls.__name__ == "LegacyAuthEnabledCheck" for cls in _REGISTRY)
