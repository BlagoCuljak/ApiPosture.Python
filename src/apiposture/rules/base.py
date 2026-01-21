"""Base class for security rules."""

from abc import ABC, abstractmethod
from collections.abc import Iterator

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import Severity
from apiposture.core.models.finding import Finding


class SecurityRule(ABC):
    """Base class for security rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier (e.g., 'AP001')."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable rule name."""
        ...

    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Default severity level."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Rule description."""
        ...

    @abstractmethod
    def evaluate(self, endpoint: Endpoint) -> Iterator[Finding]:
        """
        Evaluate the rule against an endpoint.

        Args:
            endpoint: The endpoint to evaluate

        Yields:
            Findings for any violations
        """
        ...

    def create_finding(
        self,
        endpoint: Endpoint,
        message: str,
        recommendation: str = "",
        severity: Severity | None = None,
    ) -> Finding:
        """Helper to create a finding with standard fields."""
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=severity or self.severity,
            message=message,
            endpoint=endpoint,
            recommendation=recommendation or self._default_recommendation(),
        )

    def _default_recommendation(self) -> str:
        """Default recommendation for this rule."""
        return ""
