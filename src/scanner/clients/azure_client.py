"""Read-only Azure client wrapper.

This module provides the architectural enforcement of the read-only guarantee
for Azure SDK clients. Check implementations receive a ReadOnlyAzureClient
and can ONLY call methods that begin with allowed prefixes (get, list).

Any other attribute access, including mutating methods (create, update, delete,
begin_*), raises ReadOnlyViolationError immediately.
"""

from scanner.clients.aws_client import ReadOnlyViolationError


class ReadOnlyAzureServiceProxy:
    """Proxy that allows only read methods, blocking everything else by default."""

    ALLOWED_PREFIXES = ("get", "list")

    def __init__(self, raw_client: object):
        self._raw_client = raw_client

    def __getattr__(self, name: str):
        if not name.startswith(self.ALLOWED_PREFIXES):
            raise ReadOnlyViolationError(
                f"Method '{name}' is not a read-only operation. "
                f"Only methods starting with {self.ALLOWED_PREFIXES} are allowed. "
                f"This scanner is strictly read-only by design."
            )
        return getattr(self._raw_client, name)


class ReadOnlyAzureClient:
    """Wraps Azure SDK management clients and exposes only read-style methods.

    Usage:
        client = ReadOnlyAzureClient(credential=DefaultAzureCredential(), subscription_id="...")
        storage_client = client.storage_accounts()
        accounts = storage_client.list()              # Works
        storage_client.create(...)                    # Raises ReadOnlyViolationError
    """

    def __init__(self, credential: object | None = None, subscription_id: str = ""):
        self._credential = credential
        self._subscription_id = subscription_id

    @property
    def subscription_id(self) -> str:
        return self._subscription_id

    def storage_accounts(self) -> ReadOnlyAzureServiceProxy:
        """Get a read-only proxy for StorageManagementClient.storage_accounts."""
        from azure.mgmt.storage import StorageManagementClient

        client = StorageManagementClient(self._credential, self._subscription_id)
        return ReadOnlyAzureServiceProxy(client.storage_accounts)

    def network_security_groups(self) -> ReadOnlyAzureServiceProxy:
        """Get a read-only proxy for NetworkManagementClient.network_security_groups."""
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(self._credential, self._subscription_id)
        return ReadOnlyAzureServiceProxy(client.network_security_groups)

    def vaults(self) -> ReadOnlyAzureServiceProxy:
        """Get a read-only proxy for KeyVaultManagementClient.vaults."""
        from azure.mgmt.keyvault import KeyVaultManagementClient

        client = KeyVaultManagementClient(self._credential, self._subscription_id)
        return ReadOnlyAzureServiceProxy(client.vaults)

    def role_assignments(self) -> ReadOnlyAzureServiceProxy:
        """Get a read-only proxy for AuthorizationManagementClient.role_assignments."""
        from azure.mgmt.authorization import AuthorizationManagementClient

        client = AuthorizationManagementClient(self._credential, self._subscription_id)
        return ReadOnlyAzureServiceProxy(client.role_assignments)

    def role_definitions(self) -> ReadOnlyAzureServiceProxy:
        """Get a read-only proxy for AuthorizationManagementClient.role_definitions."""
        from azure.mgmt.authorization import AuthorizationManagementClient

        client = AuthorizationManagementClient(self._credential, self._subscription_id)
        return ReadOnlyAzureServiceProxy(client.role_definitions)

    def pricings(self) -> ReadOnlyAzureServiceProxy:
        """Get a read-only proxy for SecurityCenter pricings."""
        from azure.mgmt.security import SecurityCenter

        client = SecurityCenter(self._credential, self._subscription_id, "")
        return ReadOnlyAzureServiceProxy(client.pricings)
