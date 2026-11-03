"""Read-only AWS client wrapper.

This module provides the architectural enforcement of the read-only guarantee.
Check implementations receive a ReadOnlyAWSClient instance and can ONLY call
methods that begin with allowed prefixes (describe_, get_, list_, head_).

Any attempt to call a mutating method (create_, put_, delete_, update_, etc.)
raises ReadOnlyViolationError immediately, preventing accidental modifications.
"""

import boto3


class ReadOnlyViolationError(Exception):
    """Raised when a check attempts to call a non-read-only API method."""

    pass


class ReadOnlyServiceProxy:
    """Proxy that intercepts all calls and blocks non-read methods.

    This is the enforcement layer — it sits between check code and the
    actual boto3 client, filtering method access by name prefix.
    """

    ALLOWED_PREFIXES = ("describe_", "get_", "list_", "head_")

    def __init__(self, raw_client: object):
        self._raw_client = raw_client

    def __getattr__(self, name: str):
        if not any(name.startswith(prefix) for prefix in self.ALLOWED_PREFIXES):
            raise ReadOnlyViolationError(
                f"Method '{name}' is not a read-only operation. "
                f"Only methods starting with {self.ALLOWED_PREFIXES} are allowed. "
                f"This scanner is strictly read-only by design."
            )
        return getattr(self._raw_client, name)


class ReadOnlyAWSClient:
    """Wraps a boto3 session and exposes only read-style API methods.

    Usage:
        client = ReadOnlyAWSClient(session=boto3.Session(profile_name="..."), region="us-east-1")
        s3 = client.service("s3")
        buckets = s3.list_buckets()       # Works
        s3.delete_bucket(Bucket="x")      # Raises ReadOnlyViolationError
    """

    def __init__(self, session: boto3.Session | None = None, region: str = "us-east-1"):
        self._session = session or boto3.Session()
        self._region = region

    @property
    def region(self) -> str:
        return self._region

    def service(self, service_name: str) -> ReadOnlyServiceProxy:
        """Get a read-only proxy for a specific AWS service."""
        raw_client = self._session.client(service_name, region_name=self._region)
        return ReadOnlyServiceProxy(raw_client)
