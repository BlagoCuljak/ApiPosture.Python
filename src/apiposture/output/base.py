"""Base class for output formatters."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from rich.console import Console

from apiposture.core.models.scan_result import ScanResult


@dataclass
class FormatterOptions:
    """Options for output formatters."""

    no_color: bool = False
    no_icons: bool = False
    group_by: str | None = None


class OutputFormatter(ABC):
    """Base class for output formatters."""

    def __init__(self, options: FormatterOptions | None = None) -> None:
        self.options = options or FormatterOptions()

    @abstractmethod
    def format(self, result: ScanResult) -> str:
        """
        Format the scan result as a string.

        Args:
            result: The scan result to format

        Returns:
            Formatted string output
        """
        ...

    def print(self, result: ScanResult, console: Console) -> None:
        """
        Print the scan result to a console.

        Override this for formatters that use rich directly.

        Args:
            result: The scan result to print
            console: Rich console to print to
        """
        console.print(self.format(result))
