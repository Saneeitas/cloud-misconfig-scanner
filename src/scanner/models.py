"""Core data models for the scanner."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Finding severity levels, ordered from most to least critical."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse a severity string (case-insensitive)."""
        return cls[value.upper()]

    def __ge__(self, other: "Severity") -> bool:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) >= order.index(other)

    def __gt__(self, other: "Severity") -> bool:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) > order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return not self.__gt__(other)

    def __lt__(self, other: "Severity") -> bool:
        return not self.__ge__(other)


@dataclass
class Finding:
    """A single detected misconfiguration."""

    check_id: str
    title: str
    severity: Severity
    resource_id: str
    region: str
    description: str
    remediation: str
    cloud_provider: str

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_id": self.resource_id,
            "region": self.region,
            "description": self.description,
            "remediation": self.remediation,
            "cloud_provider": self.cloud_provider,
        }


@dataclass
class ScanResult:
    """Aggregated scan results."""

    findings: list[Finding] = field(default_factory=list)
    checks_run: int = 0
    errors: list[str] = field(default_factory=list)
