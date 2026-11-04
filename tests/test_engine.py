"""Check discovery, filtering, and error handling in the engine."""

import pytest

from scanner.base_check import BaseCheck
from scanner.context import ScanContext
from scanner.engine import ScannerEngine
from scanner.models import Finding, ScanResult, Severity
from scanner.registry import CheckRegistry


class StubCheck(BaseCheck):
    title = "Stub"
    description = "Stub"
    remediation = "Stub"

    def run(self, context):
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                resource_id="resource",
                region="region",
                description=self.description,
                remediation=self.remediation,
                cloud_provider=self.cloud_provider,
            )
        ]


class AwsCritical(StubCheck):
    id = "AWS-CRITICAL"
    severity = Severity.CRITICAL
    cloud_provider = "aws"


class AwsMedium(StubCheck):
    id = "AWS-MEDIUM"
    severity = Severity.MEDIUM
    cloud_provider = "aws"


class AzureHigh(StubCheck):
    id = "AZ-HIGH"
    severity = Severity.HIGH
    cloud_provider = "azure"


class Broken(StubCheck):
    id = "AWS-BROKEN"
    severity = Severity.HIGH
    cloud_provider = "aws"

    def run(self, context):
        raise RuntimeError("boom")


@pytest.fixture
def stub_checks(monkeypatch):
    monkeypatch.setattr(
        CheckRegistry, "discover", classmethod(lambda cls: [AwsCritical, AwsMedium, AzureHigh])
    )


def finding_ids(result):
    return {f.check_id for f in result.findings}


def test_registry_discovers_all_aws_checks():
    ids = {check().id for check in CheckRegistry.discover()}

    assert ids == {
        "AWS-S3-001",
        "AWS-S3-002",
        "AWS-S3-003",
        "AWS-S3-004",
        "AWS-IAM-001",
        "AWS-IAM-002",
    }


@pytest.mark.usefixtures("stub_checks")
@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({}, {"AWS-CRITICAL", "AWS-MEDIUM", "AZ-HIGH"}),
        ({"provider": "aws"}, {"AWS-CRITICAL", "AWS-MEDIUM"}),
        ({"provider": "azure"}, {"AZ-HIGH"}),
        ({"severity_threshold": Severity.HIGH}, {"AWS-CRITICAL", "AZ-HIGH"}),
        ({"check_ids": ["AWS-MEDIUM"]}, {"AWS-MEDIUM"}),
    ],
    ids=["all", "aws", "azure", "severity", "check-ids"],
)
def test_engine_filters_checks(options, expected):
    result = ScannerEngine(ScanContext(), **options).run()

    assert finding_ids(result) == expected
    assert result.checks_run == len(expected)
    assert not result.incomplete


def test_failed_check_is_recorded_and_others_still_run(monkeypatch):
    monkeypatch.setattr(CheckRegistry, "discover", classmethod(lambda cls: [Broken, AwsCritical]))

    result = ScannerEngine(ScanContext()).run()

    assert finding_ids(result) == {"AWS-CRITICAL"}
    assert result.errors == ["Check AWS-BROKEN failed: boom"]
    assert result.incomplete


@pytest.mark.usefixtures("stub_checks")
def test_result_is_incomplete_when_no_checks_match():
    result = ScannerEngine(ScanContext(), check_ids=["DOES-NOT-EXIST"]).run()

    assert result.checks_run == 0
    assert result.incomplete


def test_result_is_complete_when_checks_ran_cleanly():
    assert not ScanResult(checks_run=1).incomplete
