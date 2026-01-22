"""Project analyzer that orchestrates the scanning process."""

from datetime import datetime
from pathlib import Path

from apiposture.core.analysis.source_loader import SourceLoader
from apiposture.core.classification.classifier import SecurityClassifier
from apiposture.core.configuration.loader import ApiPostureConfig
from apiposture.core.discovery.base import EndpointDiscoverer
from apiposture.core.discovery.django_drf import DjangoRESTFrameworkDiscoverer
from apiposture.core.discovery.fastapi import FastAPIEndpointDiscoverer
from apiposture.core.discovery.flask import FlaskEndpointDiscoverer
from apiposture.core.models.scan_result import ScanResult
from apiposture.rules.engine import RuleEngine


class ProjectAnalyzer:
    """Orchestrates the scanning process for a project."""

    def __init__(self, config: ApiPostureConfig | None = None) -> None:
        """
        Initialize the analyzer.

        Args:
            config: Configuration for the scan
        """
        self.config = config or ApiPostureConfig()

        # Initialize discoverers
        self.discoverers: list[EndpointDiscoverer] = [
            FastAPIEndpointDiscoverer(),
            FlaskEndpointDiscoverer(),
            DjangoRESTFrameworkDiscoverer(),
        ]

        # Initialize classifier
        self.classifier = SecurityClassifier()

        # Initialize rule engine
        active_rules = self.config.get_active_rules()
        self.rule_engine = RuleEngine(enabled_rules=active_rules)

    def analyze(self, path: Path) -> ScanResult:
        """
        Analyze a project for API security issues.

        Args:
            path: Path to the project directory or file

        Returns:
            ScanResult containing all findings
        """
        result = ScanResult(scan_path=path)

        # Get files to scan
        files = self._get_files(path)
        result.files_scanned = files

        # Scan each file
        for file_path in files:
            self._scan_file(file_path, result)

        # Classify all endpoints
        self.classifier.classify_all(result.endpoints)

        # Run security rules
        findings = self.rule_engine.evaluate_all(result.endpoints)

        # Apply suppressions
        for finding in findings:
            is_suppressed, reason = self.config.is_suppressed(
                finding.rule_id, finding.endpoint.full_route
            )
            if is_suppressed:
                finding.suppressed = True
                finding.suppression_reason = reason

        # Filter by rule enablement
        findings = [
            f for f in findings
            if self.config.is_rule_enabled(f.rule_id)
        ]

        result.findings = findings
        result.end_time = datetime.now()

        return result

    def _get_files(self, path: Path) -> list[Path]:
        """Get list of Python files to scan."""
        if path.is_file():
            if path.suffix == ".py":
                return [path]
            return []

        files: list[Path] = []

        # Use glob patterns from config
        for pattern in self.config.include_patterns:
            files.extend(path.glob(pattern))

        # Filter out excluded patterns
        filtered_files: list[Path] = []
        for file_path in files:
            relative = file_path.relative_to(path)
            excluded = False

            for exclude_pattern in self.config.exclude_patterns:
                # Check if the file matches any exclude pattern
                if file_path.match(exclude_pattern):
                    excluded = True
                    break
                # Also check the relative path as a string
                if any(
                    part.startswith(".")
                    for part in relative.parts
                    if part not in (".", "..")
                ):
                    # Skip hidden directories
                    if "__pycache__" in str(relative) or ".git" in str(relative):
                        excluded = True
                        break

            if not excluded:
                filtered_files.append(file_path)

        return sorted(filtered_files)

    def _scan_file(self, file_path: Path, result: ScanResult) -> None:
        """Scan a single file for endpoints."""
        # Parse the file
        parsed, error = SourceLoader.try_parse_file(file_path)

        if error:
            result.parse_errors[file_path] = error
            return

        if parsed is None:
            return

        # Try each discoverer
        for discoverer in self.discoverers:
            if discoverer.can_handle(parsed):
                result.frameworks_detected.add(discoverer.framework)

                for endpoint in discoverer.discover(parsed, file_path):
                    result.endpoints.append(endpoint)
