"""AWS-IAM-002: IAM user has console access but no MFA device attached.

Console access without MFA means a compromised password gives direct
account access with no second factor. This is especially dangerous for
users with elevated privileges.

Derived from the IAM best practices enforced in the AWS lab where MFA
was required for all console-enabled users.
"""

from scanner.base_check import BaseCheck
from scanner.context import ScanContext
from scanner.models import Finding, Severity


class IAMNoMFACheck(BaseCheck):
    """Detects IAM users with console access but no MFA."""

    @property
    def id(self) -> str:
        return "AWS-IAM-002"

    @property
    def title(self) -> str:
        return "IAM user has console access without MFA"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def cloud_provider(self) -> str:
        return "aws"

    @property
    def description(self) -> str:
        return (
            "The IAM user has an active console login profile but no MFA device "
            "attached. A compromised password would grant direct console access."
        )

    @property
    def remediation(self) -> str:
        return (
            "Enable MFA for the user. "
            "AWS Console: IAM > Users > Security credentials > Assign MFA device. "
            "CLI: aws iam enable-mfa-device --user-name <name> ..."
        )

    def run(self, context: ScanContext) -> list[Finding]:
        findings = []
        if not context.aws_client:
            return findings

        iam = context.aws_client.service("iam")
        users = iam.list_users().get("Users", [])

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]

            # Check if user has console access (login profile)
            try:
                iam.get_login_profile(UserName=username)
            except Exception:
                # No login profile = no console access, skip
                continue

            # Check if MFA is attached
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            if not mfa_devices:
                findings.append(Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    resource_id=user_arn,
                    region=context.aws_region or "global",
                    description=self.description,
                    remediation=self.remediation,
                    cloud_provider=self.cloud_provider,
                ))

        return findings
