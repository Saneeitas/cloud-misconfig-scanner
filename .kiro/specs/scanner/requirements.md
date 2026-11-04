# Requirements Document

## Introduction

This project is a multi-cloud security misconfiguration scanner — a Python CLI tool that audits AWS and Azure environments for common security issues and reports findings with actionable remediation guidance. It is designed as a real, extensible security tool for a public portfolio, reviewed alongside hands-on AWS/Azure security lab projects. Every check in this tool maps directly to a real finding from those lab environments.

The tool is **strictly read-only** by design: it detects and reports misconfigurations but never creates, modifies, or deletes any cloud resource. This is enforced architecturally, not just by convention.

## Glossary

- **Check**: A self-contained class implementing a common interface that evaluates a specific security misconfiguration pattern against live cloud resources
- **Finding**: A single instance of a detected misconfiguration, containing the check metadata, affected resource identifier, and remediation guidance
- **ReadOnlyClient**: A wrapper around cloud SDK clients that exposes only read/describe/get/list methods, preventing any check from accidentally invoking mutating APIs
- **CheckRegistry**: The mechanism for discovering and registering available checks — new checks are added by dropping a class file into the checks directory
- **ScanContext**: The runtime context passed to each check, containing the read-only client, target region/subscription, and scan configuration
- **Provider**: A cloud provider identifier (`"aws"` or `"azure"`) used to filter which checks execute

## Requirements

### Requirement 1: Read-Only Enforcement

**User Story:** As a user running this tool against production accounts, I need a guarantee that it will never modify any resource, so that I can scan safely without change-control approval.

#### Acceptance Criteria

1. THE scanner SHALL provide a ReadOnlyClient wrapper for each cloud provider (AWS, Azure) that exposes ONLY read/describe/get/list-style SDK methods to check implementations
2. Check classes SHALL NOT have direct access to raw boto3 or Azure SDK clients — they receive only the ReadOnlyClient wrapper via the ScanContext
3. THE ReadOnlyClient for AWS SHALL wrap boto3 clients/resources and expose only methods whose API action begins with `Describe`, `Get`, `List`, or `Head`
4. THE ReadOnlyClient for Azure SHALL wrap azure-mgmt SDK clients and expose only methods whose names begin with `get`, `list`, or similar read-only patterns
5. IF a check implementation attempts to call a non-read method, THE ReadOnlyClient SHALL raise an explicit error rather than silently forwarding the call
6. THE README SHALL prominently state the read-only guarantee in the first section

### Requirement 2: Pluggable Check Interface

**User Story:** As a developer extending this tool, I want to add a new check by creating a single class file, so that the architecture scales cleanly without editing central scripts.

#### Acceptance Criteria

1. EACH check SHALL be a Python class implementing a common `BaseCheck` abstract interface with properties: `id` (str), `title` (str), `severity` (enum: Critical/High/Medium/Low), `cloud_provider` (str: "aws" | "azure"), `description` (str), `remediation` (str)
2. EACH check SHALL implement a `run(context: ScanContext) -> list[Finding]` method that performs the evaluation and returns zero or more findings
3. THE CheckRegistry SHALL automatically discover all check classes by scanning the `checks/` directory on startup — no manual registration file required
4. A new check SHALL be addable by creating a new `.py` file in the appropriate `checks/aws/` or `checks/azure/` subdirectory containing a class that extends `BaseCheck`
5. EACH check class SHALL include a docstring explaining the security rationale in language appropriate for a security engineer audience

### Requirement 3: AWS Checks (v1 Scope)

**User Story:** As a security engineer, I want the scanner to detect the most common AWS misconfigurations that I encountered in my lab projects, so that the tool demonstrates real-world relevance.

#### Acceptance Criteria

1. Check `AWS-S3-001`: Detect S3 buckets whose bucket policy allows public/wildcard principal access (Principal: "*" or Principal: {"AWS": "*"})
2. Check `AWS-S3-002`: Detect S3 buckets with versioning disabled or suspended
3. Check `AWS-S3-003`: Detect S3 buckets without server access logging enabled
4. Check `AWS-S3-004`: Detect S3 buckets not using SSE-KMS encryption (missing or using SSE-S3/AES256 instead)
5. Check `AWS-IAM-001`: Detect IAM policies containing both `"Action": "*"` and `"Resource": "*"` in the same statement (overly permissive)
6. Check `AWS-IAM-002`: Detect IAM users with console access but no MFA device attached
7. Check `AWS-EC2-001`: Detect security groups allowing inbound 0.0.0.0/0 or ::/0 on port 22 (SSH) or 3389 (RDP)
8. Check `AWS-CT-001`: Detect when CloudTrail is not enabled or does not have a multi-region trail covering all regions

### Requirement 4: Azure Checks (v1 Scope)

**User Story:** As a security engineer, I want the scanner to detect the most common Azure misconfigurations that I encountered in my lab projects, so that the tool demonstrates real-world relevance.

#### Acceptance Criteria

1. Check `AZ-ST-001`: Detect storage accounts that allow public blob access or don't enforce secure transfer (HTTPS-only)
2. Check `AZ-ST-002`: Detect storage accounts with shared key access enabled (should use Azure AD-only auth)
3. Check `AZ-KV-001`: Detect Key Vaults NOT using the Azure RBAC permission model (still on legacy access policies)
4. Check `AZ-NSG-001`: Detect NSG inbound rules allowing source 0.0.0.0/0 or Any on port 22 or 3389
5. Check `AZ-RBAC-001`: Detect role assignments granting Owner or Contributor at subscription scope (overly broad)
6. Check `AZ-DEF-001`: Detect when Microsoft Defender for Cloud paid plans are not enabled (informational/Low severity)

### Requirement 5: CLI Interface

**User Story:** As a user, I want a clean CLI with provider selection, output format control, and filtering options, so that I can integrate this into both manual reviews and CI pipelines.

#### Acceptance Criteria

1. THE CLI SHALL be built with `click` and support the command `scanner scan`
2. THE CLI SHALL accept `--provider` with values `aws`, `azure`, or `all` (runs both if credentials available)
3. THE CLI SHALL accept `--profile <name>` for AWS credential profile selection and `--region <region>` for AWS region targeting
4. THE CLI SHALL accept `--subscription-id <id>` for Azure subscription targeting
5. THE CLI SHALL accept `--output` with values `table` (default, human-readable with color) or `json` (machine-readable)
6. THE CLI SHALL accept `--output-file <path>` to write results to a file instead of stdout (for JSON mode)
7. THE CLI SHALL accept `--severity-threshold` to filter out findings below the specified severity level
8. THE CLI SHALL accept `--checks <ids>` (comma-separated) to run only specific check IDs
9. THE CLI SHALL exit with code 0 if no findings above threshold, exit code 1 if findings exist (for CI gating)

### Requirement 6: Output Format

**User Story:** As a user, I want findings to be clearly presented with all context needed to understand and fix the issue, in both human-readable and machine-parseable formats.

#### Acceptance Criteria

1. EACH finding SHALL include: check_id, title, severity, resource_arn_or_id, region_or_subscription, description, and remediation
2. Table output SHALL use `rich` for color-coding by severity (Critical=red, High=orange, Medium=yellow, Low=blue) and SHALL be readable in a standard terminal width
3. JSON output SHALL follow a stable schema with a top-level `version` field (starting at `"1.0"`) and a `findings` array
4. JSON output SHALL include scan metadata: timestamp, provider, region/subscription, total check count, finding count by severity

### Requirement 7: Testing

**User Story:** As a developer, I want comprehensive unit tests for every check using mocked API responses, so that I can refactor safely and demonstrate code quality.

#### Acceptance Criteria

1. AWS check tests SHALL use `moto` to mock AWS API responses with fixture data representing both compliant and non-compliant resources
2. Azure check tests SHALL use `unittest.mock` to mock Azure SDK client responses with equivalent fixture patterns
3. EACH check SHALL have at minimum two test cases: one asserting the check detects a non-compliant resource, one asserting no false positive on a compliant resource
4. Tests SHALL be runnable via `pytest` with no real cloud credentials required
5. Test coverage SHALL cover the check logic meaningfully (not just "does it import without error")

### Requirement 8: CI Pipeline

**User Story:** As a developer, I want automated linting, type-checking, and test execution on every push, so that code quality is maintained.

#### Acceptance Criteria

1. THE project SHALL include a GitHub Actions workflow triggered on push and pull_request
2. THE workflow SHALL run: lint (ruff), type-check (mypy), and full pytest suite
3. THE workflow SHALL use Python 3.11+
4. THE workflow SHALL fail the build if any step produces errors

### Requirement 9: Documentation

**User Story:** As an engineer reviewing this repo, I want clear documentation explaining architecture, usage, the check catalog, and how to extend it.

#### Acceptance Criteria

1. THE README SHALL include: project description, read-only guarantee (prominent), install/quickstart, example command with example output, full check catalog table (ID, title, severity, provider), and notes tying checks to real lab findings
2. THE project SHALL include a CONTRIBUTING.md explaining the check-plugin interface with a step-by-step guide for adding a new check
3. EACH check class docstring SHALL explain the security rationale in security-engineer-appropriate language, not generic boilerplate
