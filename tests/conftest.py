"""Shared fixtures. Tests use mocked AWS only and never need real credentials."""

import os

import boto3
import pytest
from moto import mock_aws

from scanner.clients.aws_client import ReadOnlyAWSClient
from scanner.context import ScanContext

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def isolated_aws_env(monkeypatch):
    """Stop any test from picking up the developer's real AWS credentials."""
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture
def aws():
    with mock_aws():
        yield


@pytest.fixture
def context(aws):
    return ScanContext(aws_client=ReadOnlyAWSClient(region=REGION), aws_region=REGION)


@pytest.fixture
def s3(aws):
    return boto3.client("s3", region_name=REGION)


@pytest.fixture
def iam(aws):
    return boto3.client("iam", region_name=REGION)
