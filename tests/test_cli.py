"""End-to-end CLI behaviour, focused on exit codes that CI pipelines rely on."""

import json

import pytest
from click.testing import CliRunner

from scanner.cli import main

PASS_MESSAGE = "all checks passed"
INCOMPLETE_MESSAGE = "Scan incomplete"


def scan(*args):
    return CliRunner().invoke(main, ["scan", *args])


@pytest.mark.usefixtures("aws")
def test_clean_scan_exits_0():
    result = scan("--provider", "aws")

    assert result.exit_code == 0
    assert PASS_MESSAGE in result.output


def test_findings_exit_1(s3):
    s3.create_bucket(Bucket="test-bucket")

    result = scan("--provider", "aws")

    assert result.exit_code == 1
    assert "6 checks run, 3 findings" in result.output


def test_severity_threshold_hides_lower_findings(s3):
    s3.create_bucket(Bucket="test-bucket")  # Only produces Medium findings

    result = scan("--provider", "aws", "--severity-threshold", "high")

    assert result.exit_code == 0


@pytest.mark.parametrize("output", ["table", "json"])
def test_missing_credentials_are_not_reported_as_a_pass(monkeypatch, output):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")

    result = scan("--provider", "aws", "--output", output)

    assert result.exit_code == 2
    assert PASS_MESSAGE not in result.output
    assert INCOMPLETE_MESSAGE in result.output
    assert "credentials" in result.output


def test_azure_with_no_checks_is_not_reported_as_a_pass():
    result = scan("--provider", "azure")

    assert result.exit_code == 2
    assert PASS_MESSAGE not in result.output
    assert INCOMPLETE_MESSAGE in result.output


@pytest.mark.usefixtures("aws")
def test_unknown_check_id_is_not_reported_as_a_pass():
    result = scan("--provider", "aws", "--checks", "AWS-TYPO-001")

    assert result.exit_code == 2
    assert PASS_MESSAGE not in result.output


def test_json_output_file_follows_schema(s3, tmp_path):
    s3.create_bucket(Bucket="test-bucket")
    report = tmp_path / "findings.json"

    result = scan(
        "--provider", "aws",
        "--checks", "AWS-S3-002",
        "--output", "json",
        "--output-file", str(report),
    )

    assert result.exit_code == 1
    data = json.loads(report.read_text())
    assert data["version"] == "1.0"
    assert data["metadata"]["checks_run"] == 1
    assert data["metadata"]["total_findings"] == 1
    assert data["metadata"]["findings_count"]["medium"] == 1
    assert data["findings"][0]["check_id"] == "AWS-S3-002"
    assert data["findings"][0]["resource_id"] == "arn:aws:s3:::test-bucket"
    assert data["errors"] == []
