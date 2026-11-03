"""Scanner engine — orchestrates check discovery, execution, and result collection."""

import logging

from scanner.base_check import BaseCheck
from scanner.context import ScanContext
from scanner.models import Finding, ScanResult, Severity
from scanner.registry import CheckRegistry

logger = logging.getLogger(__name__)


class ScannerEngine:
    """Orchestrates the scan: discover checks, filter, execute, collect findings."""

    def __init__(
        self,
        context: ScanContext,
        provider: str = "all",
        severity_threshold: Severity = Severity.LOW,
        check_ids: list[str] | None = None,
    ):
        self._context = context
        self._provider = provider
        self._severity_threshold = severity_threshold
        self._check_ids = check_ids

    def run(self) -> ScanResult:
        """Execute the scan and return aggregated results."""
        all_checks = CheckRegistry.discover()
        filtered = self._filter_checks(all_checks)

        result = ScanResult()
        result.checks_run = len(filtered)

        for check_cls in filtered:
            check = check_cls()
            try:
                findings = check.run(self._context)
                # Filter by severity threshold
                for f in findings:
                    if f.severity >= self._severity_threshold:
                        result.findings.append(f)
            except Exception as e:
                error_msg = f"Check {check.id} failed: {e}"
                logger.warning(error_msg)
                result.errors.append(error_msg)

        return result

    def _filter_checks(self, checks: list[type[BaseCheck]]) -> list[type[BaseCheck]]:
        """Filter checks by provider, severity, and specific IDs."""
        filtered = []
        for check_cls in checks:
            check = check_cls()

            # Filter by provider
            if self._provider != "all" and check.cloud_provider != self._provider:
                continue

            # Filter by specific check IDs
            if self._check_ids and check.id not in self._check_ids:
                continue

            # Filter by severity threshold
            if check.severity < self._severity_threshold:
                continue

            filtered.append(check_cls)

        return filtered
