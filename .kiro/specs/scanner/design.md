# Design Document

## Overview

A multi-cloud security misconfiguration scanner built in Python. The architecture prioritizes three properties: **read-only safety** (enforced at the SDK wrapper layer), **extensibility** (new checks added by dropping a file), and **testability** (every check unit-testable with mocked API responses).

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI (click)                               │
│  scanner scan --provider aws --output table --severity High      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Scanner Engine                             │
│  1. Discover checks from registry                                │
│  2. Filter by provider, severity, check IDs                      │
│  3. Build ScanContext (read-only client + config)                │
│  4. Execute checks in sequence                                   │
│  5. Collect findings                                             │
│  6. Format and output                                            │
└────────────┬──────────────────────────────────┬─────────────────┘
             │                                  │
             ▼                                  ▼
┌────────────────────────┐    ┌────────────────────────────────────┐
│   ReadOnlyClient(AWS)  │    │     ReadOnlyClient(Azure)          │
│   Wraps boto3          │    │     Wraps azure-mgmt-*             │
│   Only: describe/get/  │    │     Only: get/list methods         │
│         list/head      │    │                                    │
│   Blocks: put/create/  │    │     Blocks: create/update/delete   │
│           delete/update │    │                                    │
└────────────────────────┘    └────────────────────────────────────┘
             │                                  │
             ▼                                  ▼
┌────────────────────────┐    ┌────────────────────────────────────┐
│    AWS APIs (read)     │    │      Azure APIs (read)             │
│    S3, IAM, EC2, CT    │    │      Storage, KV, Network, RBAC   │
└────────────────────────┘    └────────────────────────────────────┘
```

## Package Structure

```
cloud-misconfig-scanner/
├── src/
│   └── scanner/
│       ├── __init__.py
│       ├── cli.py                  # Click CLI commands
│       ├── engine.py               # Scanner engine (orchestrates checks)
│       ├── models.py               # Finding, Severity, CheckResult dataclasses
│       ├── registry.py             # Auto-discovers and registers checks
│       ├── base_check.py           # BaseCheck ABC
│       ├── context.py              # ScanContext (read-only client + config)
│       ├── clients/
│       │   ├── __init__.py
│       │   ├── aws_client.py       # ReadOnlyAWSClient wrapper
│       │   └── azure_client.py     # ReadOnlyAzureClient wrapper
│       ├── checks/
│       │   ├── __init__.py
│       │   ├── aws/
│       │   │   ├── __init__.py
│       │   │   ├── s3_public_policy.py       # AWS-S3-001
│       │   │   ├── s3_versioning.py          # AWS-S3-002
│       │   │   ├── s3_logging.py             # AWS-S3-003
│       │   │   ├── s3_encryption.py          # AWS-S3-004
│       │   │   ├── iam_overly_permissive.py  # AWS-IAM-001
│       │   │   ├── iam_no_mfa.py             # AWS-IAM-002
│       │   │   ├── sg_open_ssh_rdp.py        # AWS-EC2-001
│       │   │   └── cloudtrail_disabled.py    # AWS-CT-001
│       │   └── azure/
│       │       ├── __init__.py
│       │       ├── storage_public_access.py  # AZ-ST-001
│       │       ├── storage_shared_key.py     # AZ-ST-002
│       │       ├── keyvault_rbac.py          # AZ-KV-001
│       │       ├── nsg_open_ssh_rdp.py       # AZ-NSG-001
│       │       ├── rbac_broad_scope.py       # AZ-RBAC-001
│       │       └── defender_disabled.py      # AZ-DEF-001
│       └── formatters/
│           ├── __init__.py
│           ├── table.py            # Rich table output
│           └── json_output.py      # JSON output
├── tests/
│   ├── __init__.py
│   ├── conftest.py                 # Shared fixtures
│   ├── test_aws_checks/
│   │   ├── __init__.py
│   │   ├── test_s3_public_policy.py
│   │   ├── test_s3_versioning.py
│   │   ├── test_s3_logging.py
│   │   ├── test_s3_encryption.py
│   │   ├── test_iam_overly_permissive.py
│   │   ├── test_iam_no_mfa.py
│   │   ├── test_sg_open_ssh_rdp.py
│   │   └── test_cloudtrail_disabled.py
│   ├── test_azure_checks/
│   │   ├── __init__.py
│   │   ├── test_storage_public_access.py
│   │   ├── test_storage_shared_key.py
│   │   ├── test_keyvault_rbac.py
│   │   ├── test_nsg_open_ssh_rdp.py
│   │   ├── test_rbac_broad_scope.py
│   │   └── test_defender_disabled.py
│   ├── test_engine.py
│   ├── test_registry.py
│   └── test_clients.py
├── .github/
│   └── workflows/
│       └── ci.yml
├── pyproject.toml                  # Project config, dependencies, entry point
├── README.md
├── CONTRIBUTING.md
└── .gitignore
```

## Core Design Decisions

### 1. Read-Only Client — Architectural Enforcement

The read-only guarantee is **structural**, not just a convention. Check implementations never touch raw SDK clients.

```python
class ReadOnlyAWSClient:
    """Wraps boto3 and exposes ONLY read-style API methods.
    
    Any attempt to call a mutating method raises ReadOnlyViolationError.
    This is the architectural enforcement of the read-only guarantee.
    """
    
    ALLOWED_PREFIXES = ("describe_", "get_", "list_", "head_")
    
    def __init__(self, session: boto3.Session, region: str):
        self._session = session
        self._region = region
    
    def client(self, service: str) -> "ReadOnlyServiceProxy":
        raw_client = self._session.client(service, region_name=self._region)
        return ReadOnlyServiceProxy(raw_client, self.ALLOWED_PREFIXES)


class ReadOnlyServiceProxy:
    """Proxy that intercepts all calls and blocks non-read methods."""
    
    def __getattr__(self, name: str):
        if not any(name.startswith(p) for p in self._allowed_prefixes):
            raise ReadOnlyViolationError(
                f"Method '{name}' is not a read-only operation. "
                f"Only methods starting with {self._allowed_prefixes} are allowed."
            )
        return getattr(self._raw_client, name)
```

The Azure equivalent wraps `azure-mgmt-*` clients similarly, allowing only `get`, `list`, `list_by_*` method patterns.

### 2. BaseCheck ABC

```python
from abc import ABC, abstractmethod
from enum import Enum

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class BaseCheck(ABC):
    """Abstract base for all misconfiguration checks."""
    
    @property
    @abstractmethod
    def id(self) -> str: ...
    
    @property
    @abstractmethod
    def title(self) -> str: ...
    
    @property
    @abstractmethod
    def severity(self) -> Severity: ...
    
    @property
    @abstractmethod
    def cloud_provider(self) -> str: ...  # "aws" | "azure"
    
    @property
    @abstractmethod
    def description(self) -> str: ...
    
    @property
    @abstractmethod
    def remediation(self) -> str: ...
    
    @abstractmethod
    def run(self, context: ScanContext) -> list[Finding]: ...
```

### 3. Auto-Discovery Registry

```python
class CheckRegistry:
    """Discovers check classes by scanning checks/ subdirectories."""
    
    @classmethod
    def discover(cls) -> list[type[BaseCheck]]:
        """Import all modules in checks/aws/ and checks/azure/,
        find all BaseCheck subclasses, return them."""
        checks = []
        for module in _iter_check_modules():
            for obj in vars(module).values():
                if (isinstance(obj, type) 
                    and issubclass(obj, BaseCheck) 
                    and obj is not BaseCheck):
                    checks.append(obj)
        return checks
```

New checks are discovered automatically — no registration step needed.

### 4. Finding Model

```python
@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    resource_id: str        # ARN for AWS, resource ID for Azure
    region: str             # AWS region or Azure subscription/location
    description: str
    remediation: str
    cloud_provider: str     # "aws" | "azure"
```

### 5. ScanContext

```python
@dataclass
class ScanContext:
    """Runtime context passed to each check's run() method."""
    
    # Read-only client for the target provider
    aws_client: ReadOnlyAWSClient | None = None
    azure_client: ReadOnlyAzureClient | None = None
    
    # Targeting
    aws_region: str | None = None
    azure_subscription_id: str | None = None
```

### 6. Scanner Engine Flow

```
1. CLI parses arguments
2. Engine builds ScanContext (creates read-only clients from credentials)
3. Registry.discover() finds all check classes
4. Engine filters checks by: provider, severity_threshold, specific check IDs
5. Engine iterates filtered checks, calling check.run(context)
6. Engine collects all Finding objects
7. Formatter renders findings (table or JSON)
8. CLI exits with code 0 (clean) or 1 (findings above threshold)
```

### 7. Output Formats

**Table (Rich):**
```
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check ID    ┃ Title                          ┃ Severity ┃ Resource               ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ AWS-S3-001  │ S3 bucket allows public access │ Critical │ arn:aws:s3:::my-bucket │
│ AWS-EC2-001 │ SG allows SSH from 0.0.0.0/0   │ High     │ sg-0abc123def          │
│ AZ-KV-001   │ Key Vault not using RBAC       │ Medium   │ /subscriptions/.../kv  │
└─────────────┴────────────────────────────────┴──────────┴────────────────────────┘
```

**JSON:**
```json
{
  "version": "1.0",
  "metadata": {
    "timestamp": "2026-08-09T12:00:00Z",
    "provider": "aws",
    "region": "us-east-1",
    "checks_run": 8,
    "findings_count": { "critical": 1, "high": 2, "medium": 1, "low": 0 }
  },
  "findings": [...]
}
```

### 8. Testing Strategy

| Layer | Tool | Approach |
|-------|------|----------|
| AWS checks | moto | Mock entire AWS service, create compliant + non-compliant fixtures, assert findings |
| Azure checks | unittest.mock | Patch Azure SDK client methods, return mock response objects |
| Engine | pytest | Test filtering, ordering, context building |
| Registry | pytest | Test auto-discovery with a temp check module |
| CLI | click.testing.CliRunner | Integration test full command execution |

**Test pattern for each check:**
```python
@moto.mock_s3
def test_detects_public_bucket():
    # Create a non-compliant bucket (public policy)
    # Run the check
    # Assert 1 finding with correct ID and resource ARN

@moto.mock_s3  
def test_passes_private_bucket():
    # Create a compliant bucket (no public access)
    # Run the check
    # Assert 0 findings (no false positive)
```

### 9. Dependencies

```toml
[project]
requires-python = ">=3.11"
dependencies = [
    "click>=8.0",
    "rich>=13.0",
    "boto3>=1.28",
    "azure-mgmt-storage>=21.0",
    "azure-mgmt-network>=25.0",
    "azure-mgmt-keyvault>=10.0",
    "azure-mgmt-authorization>=4.0",
    "azure-mgmt-security>=6.0",
    "azure-identity>=1.14",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "moto[s3,iam,ec2,cloudtrail]>=4.0",
    "ruff>=0.1",
    "mypy>=1.5",
]

[project.scripts]
scanner = "scanner.cli:main"
```

### 10. CI Workflow

```yaml
name: CI
on: [push, pull_request]
jobs:
  lint-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -e ".[dev]"
      - run: ruff check src/ tests/
      - run: mypy src/scanner/
      - run: pytest tests/ -v --tb=short
```

### 11. Check Severity Classification

| Severity | Criteria | Examples |
|----------|----------|---------|
| Critical | Direct public data exposure or full account compromise | S3 public policy, IAM `*:*` |
| High | Significant attack surface expansion | SSH open to internet, no MFA on console users |
| Medium | Security best practice gap with indirect risk | No versioning, no logging, legacy KV access |
| Low | Informational or defense-in-depth gap | Defender not enabled, shared key access |

### 12. Error Handling

- If credentials are missing for a provider, the engine skips that provider with a warning (not a crash)
- If an individual check throws an unexpected exception, the engine logs the error and continues with remaining checks
- Permission errors (AccessDenied) on specific API calls are caught per-check and reported as a warning, not a finding
