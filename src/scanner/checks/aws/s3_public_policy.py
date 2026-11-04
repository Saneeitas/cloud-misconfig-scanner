"""AWS-S3-001: S3 bucket policy allows public/wildcard principal access.

An Allow statement with Principal: "*" or Principal: {"AWS": "*"} can grant
access to any authenticated or anonymous caller on the internet, exposing the
bucket's data to anyone who finds it.

Deny statements are skipped because a Deny with a wildcard principal restricts
access (for example, the standard enforce-TLS policy). Allow statements with a
Condition are still flagged: only some conditions limit who can call, so they
need human review.

This check was derived from the S3 hardening phase of the AWS security lab,
where bucket policies were locked to specific IAM principal ARNs only.
"""

import json

from scanner.base_check import BaseCheck
from scanner.context import ScanContext
from scanner.models import Finding, Severity


class S3PublicPolicyCheck(BaseCheck):
    """Detects S3 buckets with bucket policies allowing public/wildcard access."""

    @property
    def id(self) -> str:
        return "AWS-S3-001"

    @property
    def title(self) -> str:
        return "S3 bucket policy allows public/wildcard principal access"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def cloud_provider(self) -> str:
        return "aws"

    @property
    def description(self) -> str:
        return (
            "The bucket policy contains a statement with Principal set to '*' or "
            "'{\"AWS\": \"*\"}', granting access to any entity. This can lead to "
            "unauthorized data access or exfiltration."
        )

    @property
    def remediation(self) -> str:
        return (
            "Replace wildcard principals with specific IAM ARNs in the bucket policy. "
            "AWS Console: S3 > Bucket > Permissions > Bucket Policy. "
            "CLI: aws s3api put-bucket-policy --bucket <name> --policy <file>"
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
                policy_response = s3.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(policy_response["Policy"])

                statements = policy.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for statement in statements:
                    if statement.get("Effect") != "Allow":
                        continue
                    principal = statement.get("Principal", {})
                    if self._is_public_principal(principal):
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
                        break  # One finding per bucket is enough
            except Exception:
                # No bucket policy or access denied — not a finding
                continue

        return findings

    @staticmethod
    def _is_public_principal(principal) -> bool:
        """Check if the principal is a wildcard (public)."""
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_value = principal.get("AWS", "")
            if aws_value == "*" or (isinstance(aws_value, list) and "*" in aws_value):
                return True
        return False
