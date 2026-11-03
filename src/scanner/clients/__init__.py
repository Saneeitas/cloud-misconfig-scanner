"""Read-only cloud SDK client wrappers."""

from scanner.clients.aws_client import ReadOnlyAWSClient
from scanner.clients.azure_client import ReadOnlyAzureClient

__all__ = ["ReadOnlyAWSClient", "ReadOnlyAzureClient"]
