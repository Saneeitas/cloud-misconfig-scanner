"""The read-only guarantee: proxies allow reads and block everything else."""

from unittest.mock import MagicMock

import pytest

from scanner.clients.aws_client import (
    ReadOnlyAWSClient,
    ReadOnlyServiceProxy,
    ReadOnlyViolationError,
)
from scanner.clients.azure_client import ReadOnlyAzureServiceProxy


@pytest.mark.parametrize(
    "method",
    ["list_buckets", "get_bucket_policy", "describe_instances", "head_bucket"],
)
def test_aws_proxy_allows_read_methods(method):
    raw = MagicMock()

    assert getattr(ReadOnlyServiceProxy(raw), method) is getattr(raw, method)


@pytest.mark.parametrize(
    "method",
    ["delete_bucket", "put_bucket_policy", "create_user", "update_user", "generate_presigned_url"],
)
def test_aws_proxy_blocks_other_methods(method):
    with pytest.raises(ReadOnlyViolationError):
        getattr(ReadOnlyServiceProxy(MagicMock()), method)


def test_aws_blocked_call_never_reaches_the_account(s3):
    s3.create_bucket(Bucket="keep-me")
    proxy = ReadOnlyAWSClient(region="us-east-1").service("s3")

    with pytest.raises(ReadOnlyViolationError):
        proxy.delete_bucket(Bucket="keep-me")

    assert [b["Name"] for b in proxy.list_buckets()["Buckets"]] == ["keep-me"]


@pytest.mark.parametrize("method", ["get", "list", "get_properties", "list_by_resource_group"])
def test_azure_proxy_allows_read_methods(method):
    raw = MagicMock()

    assert getattr(ReadOnlyAzureServiceProxy(raw), method) is getattr(raw, method)


@pytest.mark.parametrize(
    "method",
    [
        "create",
        "update",
        "delete",
        "begin_create_or_update",
        "begin_delete",
        "begin_update",
        "begin_failover",
        "regenerate_key",
        "purge_deleted",
    ],
)
def test_azure_proxy_blocks_other_methods(method):
    with pytest.raises(ReadOnlyViolationError):
        getattr(ReadOnlyAzureServiceProxy(MagicMock()), method)
