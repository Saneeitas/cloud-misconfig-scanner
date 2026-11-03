"""AWS-S3-002: S3 bucket has versioning disabled.

Versioning protects against accidental deletion and provides an audit trail
of object modifications. Without it, deleted or overwritten data is permanently
lost — critical for compliance and incident response.

Derived from the S3 phase of the AWS lab where versioning was enabled as a
defense-in-depth data protection control.
"""

from scanner.base_check import BaseCheck
from scanner.context import ScanContext
from scanner.models import Finding, Severity


class S3VersioningCheck(BaseCheck):
    """Detects S3 buckets with versioning disabled or suspended."""

    @property
    def id(self) -> str:
        return "AWS-S3-002"

    @property
    def title(self) -> str:
        return "S3 bucket versioning is disabled"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def cloud_provider(self) -> str:
        return "aws"

    @property
    def description(self) -> str:
        return (
            "The bucket does not have versioning enabled. Without versioning, "
            "accidental deletions or overwrites are permanent and unrecoverable."
        )

    @property
    def remediation(self) -> str:
        return (
            "Enable versioning on the bucket. "
            "AWS Console: S3 > Bucket > Properties > Bucket Versioning > Enable. "
            "CLI: aws s3api put-bucket-versioning --bucket <name> "
            "--versioning-configuration Status=Enabled"
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
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                status = versioning.get("Status", "")
                if status != "Enabled":
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
                continue

        return findings
