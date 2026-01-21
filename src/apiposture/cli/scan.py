"""Scan command implementation."""

import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from apiposture.core.models.enums import (
    Framework,
    HttpMethod,
    SecurityClassification,
    Severity,
)

console = Console()


class OutputFormat(str, Enum):
    """Output format options."""

    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"


class SortBy(str, Enum):
    """Sort options for results."""

    SEVERITY = "severity"
    ROUTE = "route"
    METHOD = "method"
    CLASSIFICATION = "classification"


class SortDir(str, Enum):
    """Sort direction."""

    ASC = "asc"
    DESC = "desc"


class GroupBy(str, Enum):
    """Grouping options."""

    FILE = "file"
    CLASSIFICATION = "classification"
    RULE = "rule"
    FRAMEWORK = "framework"


def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to scan (file or directory)",
        exists=True,
        resolve_path=True,
    ),
    output: OutputFormat = typer.Option(
        OutputFormat.TERMINAL,
        "--output",
        "-o",
        help="Output format",
    ),
    output_file: Path | None = typer.Option(
        None,
        "--output-file",
        "-f",
        help="Write output to file",
    ),
    config: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file (.apiposture.yaml)",
    ),
    severity: Severity = typer.Option(
        Severity.INFO,
        "--severity",
        help="Minimum severity to report",
    ),
    fail_on: Severity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 if findings at this severity or above",
    ),
    sort_by: SortBy = typer.Option(
        SortBy.SEVERITY,
        "--sort-by",
        help="Sort results by field",
    ),
    sort_dir: SortDir = typer.Option(
        SortDir.DESC,
        "--sort-dir",
        help="Sort direction",
    ),
    classification: list[SecurityClassification] | None = typer.Option(
        None,
        "--classification",
        help="Filter by security classification",
    ),
    method: list[HttpMethod] | None = typer.Option(
        None,
        "--method",
        help="Filter by HTTP method",
    ),
    route_contains: str | None = typer.Option(
        None,
        "--route-contains",
        help="Filter routes containing substring",
    ),
    framework: list[Framework] | None = typer.Option(
        None,
        "--framework",
        help="Filter by framework",
    ),
    rule: list[str] | None = typer.Option(
        None,
        "--rule",
        help="Filter by rule ID (e.g., AP001)",
    ),
    group_by: GroupBy | None = typer.Option(
        None,
        "--group-by",
        help="Group results by field",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable colored output",
    ),
    no_icons: bool = typer.Option(
        False,
        "--no-icons",
        help="Disable icons in output",
    ),
) -> None:
    """Scan a Python project for API security issues."""
    # Import here to avoid circular imports
    from apiposture.core.analysis.project_analyzer import ProjectAnalyzer
    from apiposture.core.configuration.loader import ConfigLoader
    from apiposture.output.base import FormatterOptions
    from apiposture.output.json_output import JsonFormatter
    from apiposture.output.markdown import MarkdownFormatter
    from apiposture.output.terminal import TerminalFormatter

    # Load configuration
    config_data = None
    if config and config.exists():
        config_data = ConfigLoader.load(config)
    elif (path / ".apiposture.yaml").exists():
        config_data = ConfigLoader.load(path / ".apiposture.yaml")
    elif (path / ".apiposture.yml").exists():
        config_data = ConfigLoader.load(path / ".apiposture.yml")

    # Run analysis
    analyzer = ProjectAnalyzer(config=config_data)
    result = analyzer.analyze(path)

    # Filter findings by minimum severity
    result.findings = [f for f in result.findings if f.severity >= severity]

    # Filter by classification
    if classification:
        result.endpoints = [e for e in result.endpoints if e.classification in classification]
        result.findings = [f for f in result.findings if f.endpoint.classification in classification]

    # Filter by method
    if method:
        result.endpoints = [e for e in result.endpoints if any(m in method for m in e.methods)]
        result.findings = [f for f in result.findings if any(m in method for m in f.endpoint.methods)]

    # Filter by route
    if route_contains:
        result.endpoints = [e for e in result.endpoints if route_contains in e.full_route]
        result.findings = [f for f in result.findings if route_contains in f.endpoint.full_route]

    # Filter by framework
    if framework:
        result.endpoints = [e for e in result.endpoints if e.framework in framework]
        result.findings = [f for f in result.findings if f.endpoint.framework in framework]

    # Filter by rule
    if rule:
        result.findings = [f for f in result.findings if f.rule_id in rule]

    # Sort findings
    reverse = sort_dir == SortDir.DESC
    if sort_by == SortBy.SEVERITY:
        result.findings.sort(key=lambda f: f.severity.order, reverse=reverse)
    elif sort_by == SortBy.ROUTE:
        result.findings.sort(key=lambda f: f.endpoint.full_route, reverse=reverse)
    elif sort_by == SortBy.METHOD:
        result.findings.sort(key=lambda f: f.endpoint.display_methods, reverse=reverse)
    elif sort_by == SortBy.CLASSIFICATION:
        result.findings.sort(key=lambda f: f.endpoint.classification.value, reverse=reverse)

    # Create formatter options
    options = FormatterOptions(
        no_color=no_color,
        no_icons=no_icons,
        group_by=group_by.value if group_by else None,
    )

    # Select formatter
    if output == OutputFormat.JSON:
        formatter = JsonFormatter(options)
    elif output == OutputFormat.MARKDOWN:
        formatter = MarkdownFormatter(options)
    else:
        formatter = TerminalFormatter(options)

    # Format output
    output_str = formatter.format(result)

    # Write output
    if output_file:
        output_file.write_text(output_str)
        console.print(f"Output written to {output_file}")
    else:
        if output == OutputFormat.TERMINAL:
            # TerminalFormatter uses rich directly
            formatter.print(result, console)
        else:
            console.print(output_str)

    # Exit with error code if findings at fail_on severity
    if fail_on and result.findings_at_or_above(fail_on):
        sys.exit(1)
