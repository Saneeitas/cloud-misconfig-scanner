"""AWS-IAM-001: IAM policy contains Action: * and Resource: * (overly permissive).

A policy statement with both Action: "*" and Resource: "*" grants full
administrative access to the entire AWS account. This violates least-privilege
and creates a single point of compromise — if the principal is breached,
the attacker has unrestricted access.

Derived from the IAM review in the AWS lab where policies were scoped to
specific actions and resource ARNs.
"""

import json

from scanner.base_check import BaseCheck
from scanner.context import ScanContext
from scanner.models import Finding, Severity


class IAMOverlyPermissiveCheck(BaseCheck):
    """Detects IAM policies with Action: * and Resource: * in the same statement."""

    @property
    def id(self) -> str:
        return "AWS-IAM-001"

    @property
    def title(self) -> str:
        return "IAM policy grants full administrative access (Action:* Resource:*)"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def cloud_provider(self) -> str:
        return "aws"

    @property
    def description(self) -> str:
        return (
            "An IAM policy contains a statement with both Action: '*' and Resource: '*', "
            "granting unrestricted access to all AWS services and resources. This is the "
            "most dangerous IAM misconfiguration possible."
        )

    @property
    def remediation(self) -> str:
        return (
            "Replace wildcard actions/resources with specific permissions. "
            "Use AWS Access Analyzer to identify unused permissions and scope down. "
            "AWS Console: IAM > Policies > Edit > Replace '*' with specific actions."
        )

    def run(self, context: ScanContext) -> list[Finding]:
        findings = []
        if not context.aws_client:
            return findings

        iam = context.aws_client.service("iam")

        # Check customer-managed policies
        paginator_params = {"Scope": "Local"}
        policies = iam.list_policies(**paginator_params).get("Policies", [])

        for policy in policies:
            policy_arn = policy["Arn"]
            version_id = policy["DefaultVersionId"]
            try:
                version = iam.get_policy_version(
                    PolicyArn=policy_arn, VersionId=version_id
                )
                document = version["PolicyVersion"]["Document"]
                if isinstance(document, str):
                    document = json.loads(document)

                statements = document.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]

                    if "*" in actions and "*" in resources:
                        findings.append(Finding(
                            check_id=self.id,
                            title=self.title,
                            severity=self.severity,
                            resource_id=policy_arn,
                            region=context.aws_region or "global",
                            description=self.description,
                            remediation=self.remediation,
                            cloud_provider=self.cloud_provider,
                        ))
                        break
            except Exception:
                continue

        return findings
