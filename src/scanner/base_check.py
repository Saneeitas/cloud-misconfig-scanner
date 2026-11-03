"""Abstract base class for all misconfiguration checks."""

from abc import ABC, abstractmethod

from scanner.models import Finding, Severity


class BaseCheck(ABC):
    """Abstract base for all security misconfiguration checks.

    Every check must implement all abstract properties and the run() method.
    Check classes are auto-discovered from the checks/ directory — no manual
    registration required.
    """

    @property
    @abstractmethod
    def id(self) -> str:
        """Unique check identifier (e.g., 'AWS-S3-001')."""
        ...

    @property
    @abstractmethod
    def title(self) -> str:
        """Short human-readable title."""
        ...

    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Severity level of findings produced by this check."""
        ...

    @property
    @abstractmethod
    def cloud_provider(self) -> str:
        """Cloud provider this check targets: 'aws' or 'azure'."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """What this check evaluates and why it matters."""
        ...

    @property
    @abstractmethod
    def remediation(self) -> str:
        """Concrete fix guidance referencing the actual console or CLI action."""
        ...

    @abstractmethod
    def run(self, context: "ScanContext") -> list[Finding]:  # noqa: F821
        """Execute the check and return findings.

        Args:
            context: ScanContext containing the read-only client and targeting info.

        Returns:
            List of Finding objects (empty if resource is compliant).
        """
        ...
