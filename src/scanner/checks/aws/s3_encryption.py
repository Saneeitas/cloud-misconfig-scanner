"""AWS-S3-004: S3 bucket not using SSE-KMS encryption.

SSE-KMS provides customer-managed key control, audit trail via CloudTrail,
and the ability to revoke access by disabling the key. SSE-S3 (AES256) is
AWS-managed and lacks these controls.

Derived from the KMS phase where a customer-managed key was created and
applied to the S3 bucket via bucket-level encryption configuration.
"""

from scanner.base_check import BaseCheck
from scanner.context import ScanContext
from scanner.models import Finding, Severity


class S3EncryptionCheck(BaseCheck):
    """Detects S3 buckets not using SSE-KMS encryption."""

    @property
    def id(self) -> str:
        return "AWS-S3-004"

    @property
    def title(self) -> str:
        return "S3 bucket is not using SSE-KMS encryption"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def cloud_provider(self) -> str:
        return "aws"

    @property
    def description(self) -> str:
        return (
            "The bucket's default encryption is not set to SSE-KMS. Using a "
            "customer-managed KMS key provides key rotation control, CloudTrail "
            "audit of decrypt operations, and the ability to revoke access."
        )

    @property
    def remediation(self) -> str:
        return (
            "Set default encryption to SSE-KMS with a customer-managed key. "
            "AWS Console: S3 > Bucket > Properties > Default encryption > SSE-KMS. "
            "CLI: aws s3api put-bucket-encryption --bucket <name> "
            "--server-side-encryption-configuration '{...}'"
        )

    def run(self, context: ScanContext) -> list[Finding]:
        findings = []
        if not context.aws_client:
            return findings

        s3 = context.aws_client.service("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                uses_kms = any(
                    rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                    == "aws:kms"
                    for rule in rules
                )
                if not uses_kms:
                    findings.append(Finding(
                        check_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        region=context.aws_region or "global",
                        description=self.description,
                        remediation=self.remediation,
                        cloud_provider=self.cloud_provider,
                    ))
            except Exception:
                # No encryption config = not using KMS
                findings.append(Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=context.aws_region or "global",
                    description=self.description,
                    remediation=self.remediation,
                    cloud_provider=self.cloud_provider,
                ))

        return findings
