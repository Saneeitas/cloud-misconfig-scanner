"""AWS-S3-003: S3 bucket has server access logging disabled.

Server access logging records all requests made to a bucket. Without it,
there's no visibility into who accessed what data and when — making incident
investigation and compliance auditing impossible.

Derived from the S3 phase where access logging to a dedicated log bucket
was configured as a core security control.
"""

from scanner.base_check import BaseCheck
from scanner.context import ScanContext
from scanner.models import Finding, Severity


class S3LoggingCheck(BaseCheck):
    """Detects S3 buckets without server access logging enabled."""

    @property
    def id(self) -> str:
        return "AWS-S3-003"

    @property
    def title(self) -> str:
        return "S3 bucket server access logging is disabled"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def cloud_provider(self) -> str:
        return "aws"

    @property
    def description(self) -> str:
        return (
            "The bucket does not have server access logging enabled. Without logging, "
            "there is no record of data access for security auditing or incident response."
        )

    @property
    def remediation(self) -> str:
        return (
            "Enable server access logging targeting a dedicated log bucket. "
            "AWS Console: S3 > Bucket > Properties > Server access logging > Enable. "
            "CLI: aws s3api put-bucket-logging --bucket <name> "
            "--bucket-logging-status '{\"LoggingEnabled\":{...}}'"
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
                logging_config = s3.get_bucket_logging(Bucket=bucket_name)
                if "LoggingEnabled" not in logging_config:
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
