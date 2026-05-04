"""Thin Microsoft Graph API client.

Handles MSAL token acquisition (client credentials flow / app-only auth) and
common Graph patterns: paginated GET, error handling, beta vs v1.0 endpoints.

Designed to be **read-only** — never makes POST/PATCH/DELETE calls. The auditor
asks the tenant admin for an Entra app registration with these permissions:

    Microsoft Graph (Application):
        - Directory.Read.All
        - Policy.Read.All
        - SecurityEvents.Read.All
        - AuditLog.Read.All
        - Mail.Read         (only if scanning forwarding rules)
        - Reports.Read.All

This module is intentionally narrow: it does not depend on the Microsoft Graph
Python SDK because that SDK is heavy, version-fragile, and overkill for read-
only endpoints. We just need an authenticated requests session.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Iterator
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


GRAPH_V1 = "https://graph.microsoft.com/v1.0/"
GRAPH_BETA = "https://graph.microsoft.com/beta/"
LOGIN_HOST = "https://login.microsoftonline.com/"


class GraphError(Exception):
    """Wraps non-200 responses from Graph."""

    def __init__(self, status: int, body: str, url: str) -> None:
        super().__init__(f"Graph {status} on {url}: {body[:300]}")
        self.status = status
        self.body = body
        self.url = url


class GraphClient:
    """Authenticated client for Microsoft Graph (app-only / client credentials)."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        beta: bool = False,
        session: Any = None,  # requests.Session-like, injectable for tests
    ) -> None:
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.base = GRAPH_BETA if beta else GRAPH_V1
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._session = session  # set lazily so tests can inject

    def _ensure_session(self) -> Any:
        if self._session is None:
            import requests  # type: ignore
            self._session = requests.Session()
        return self._session

    # ------- auth -------

    def _acquire_token(self) -> str:
        """Client credentials flow via OAuth2 token endpoint."""
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token

        url = f"{LOGIN_HOST}{self.tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
        sess = self._ensure_session()
        resp = sess.post(url, data=data, timeout=30)
        if resp.status_code != 200:
            raise GraphError(resp.status_code, resp.text, url)
        body = resp.json()
        self._token = body["access_token"]
        self._token_expires_at = time.time() + int(body.get("expires_in", 3600))
        return self._token

    # ------- requests -------

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET a single Graph resource. Path is relative to /v1.0/ or /beta/."""
        url = urljoin(self.base, path.lstrip("/"))
        token = self._acquire_token()
        sess = self._ensure_session()
        resp = sess.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=60,
        )
        if resp.status_code == 429:
            retry = int(resp.headers.get("Retry-After", "10"))
            logger.warning("Rate limited; sleeping %ds", retry)
            time.sleep(retry)
            return self.get(path, params=params)
        if resp.status_code != 200:
            raise GraphError(resp.status_code, resp.text, url)
        return resp.json()

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        """GET all pages of a Graph collection. Yields each item."""
        page = self.get(path, params=params)
        while True:
            for item in page.get("value", []):
                yield item
            next_link = page.get("@odata.nextLink")
            if not next_link:
                return
            token = self._acquire_token()
            sess = self._ensure_session()
            resp = sess.get(
                next_link,
                headers={"Authorization": f"Bearer {token}"},
                timeout=60,
            )
            if resp.status_code != 200:
                raise GraphError(resp.status_code, resp.text, next_link)
            page = resp.json()
