"""Base class and registry for security checks."""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from ..graph import GraphClient, GraphError
from ..models import CheckResult, Finding, Status


class Check(ABC):
    """Base class for all posture checks."""

    check_id: str = ""
    name: str = ""
    category: str = ""
    description: str = ""

    @abstractmethod
    def run(self, client: GraphClient) -> list[Finding]:
        """Execute the check and return any findings (empty list = pass)."""

    def execute(self, client: GraphClient) -> CheckResult:
        """Run the check with timing and error handling."""
        start = time.perf_counter()
        try:
            findings = self.run(client)
            status = Status.FAIL if findings else Status.PASS
            # If only LOW or INFO findings, consider it a Warn rather than Fail.
            if findings and all(f.severity.value in ("Low", "Informational") for f in findings):
                status = Status.WARN
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                category=self.category,
                status=status,
                findings=findings,
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except GraphError as e:
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                category=self.category,
                status=Status.ERROR,
                error_message=f"Graph API error: {e}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as e:  # noqa: BLE001
            return CheckResult(
                check_id=self.check_id,
                name=self.name,
                category=self.category,
                status=Status.ERROR,
                error_message=f"{type(e).__name__}: {e}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )


# Registry — checks self-register via decorator
_REGISTRY: list[type[Check]] = []


def register(cls: type[Check]) -> type[Check]:
    """Decorator that registers a Check subclass."""
    _REGISTRY.append(cls)
    return cls


def all_checks() -> list[Check]:
    """Instantiate every registered check."""
    return [cls() for cls in _REGISTRY]
