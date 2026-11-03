"""Scan context — runtime state passed to each check."""

from dataclasses import dataclass

from scanner.clients.aws_client import ReadOnlyAWSClient
from scanner.clients.azure_client import ReadOnlyAzureClient


@dataclass
class ScanContext:
    """Runtime context provided to each check's run() method.

    Contains the read-only client(s) and targeting information.
    Checks access only the client for their provider.
    """

    aws_client: ReadOnlyAWSClient | None = None
    azure_client: ReadOnlyAzureClient | None = None
    aws_region: str | None = None
    azure_subscription_id: str | None = None
