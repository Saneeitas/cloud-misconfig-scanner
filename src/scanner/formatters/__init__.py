"""Output formatters for scan results."""

from scanner.formatters.json_output import format_json
from scanner.formatters.table import format_table

__all__ = ["format_table", "format_json"]
