"""AP004: Missing authentication on write endpoints."""

from collections.abc import Iterator

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import SecurityClassification, Severity
from apiposture.core.models.finding import Finding
from apiposture.rules.base import SecurityRule


class AP004MissingAuthWrites(SecurityRule):
    """
    AP004: Missing authentication on write endpoints.

    Triggers when a write endpoint (POST, PUT, DELETE, PATCH) has no authentication
    and doesn't explicitly allow anonymous access.
    """

    @property
    def rule_id(self) -> str:
        return "AP004"

    @property
    def name(self) -> str:
        return "Missing authentication on write endpoint"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "Write endpoints without any authentication configuration. "
            "These endpoints may allow unauthorized data modification."
        )

    def evaluate(self, endpoint: Endpoint) -> Iterator[Finding]:
        """Check if write endpoint is missing authentication."""
        # Only check write endpoints
        if not endpoint.is_write_endpoint:
            return

        # Only check public endpoints
        if endpoint.classification != SecurityClassification.PUBLIC:
            return

        # Skip if explicitly allowing anonymous (covered by AP002)
        if endpoint.authorization.allows_anonymous:
            return

        yield self.create_finding(
            endpoint,
            message=(
                f"Write endpoint '{endpoint.full_route}' [{endpoint.display_methods}] "
                f"has no authentication"
            ),
            recommendation=(
                "Add authentication: use Depends(get_current_user) for FastAPI, "
                "@login_required for Flask, or IsAuthenticated permission for DRF"
            ),
        )
