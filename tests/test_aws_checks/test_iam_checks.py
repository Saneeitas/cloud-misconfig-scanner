"""IAM checks, each tested against compliant and non-compliant resources."""

import json

import pytest

from scanner.checks.aws.iam_no_mfa import IAMNoMFACheck
from scanner.checks.aws.iam_overly_permissive import IAMOverlyPermissiveCheck
from scanner.models import Severity

USER = "test-user"


def create_policy(iam, statements):
    return iam.create_policy(
        PolicyName="test-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )["Policy"]["Arn"]


@pytest.mark.parametrize(
    "statements",
    [
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}],
        [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*"},
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
        ],
    ],
    ids=["single-statement", "list-form", "second-statement"],
)
def test_overly_permissive_flags_admin_policy(iam, context, statements):
    policy_arn = create_policy(iam, statements)

    findings = IAMOverlyPermissiveCheck().run(context)

    assert [f.resource_id for f in findings] == [policy_arn]
    assert findings[0].check_id == "AWS-IAM-001"
    assert findings[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    "statements",
    [
        [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*"}],
        [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::x/*"}],
        [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    ],
    ids=["scoped", "wildcard-action-only", "wildcard-resource-only", "deny"],
)
def test_overly_permissive_passes_other_policies(iam, context, statements):
    create_policy(iam, statements)

    assert IAMOverlyPermissiveCheck().run(context) == []


def create_console_user(iam):
    arn = iam.create_user(UserName=USER)["User"]["Arn"]
    iam.create_login_profile(UserName=USER, Password="Not-A-Real-Passw0rd!")
    return arn


def test_no_mfa_flags_console_user_without_mfa(iam, context):
    user_arn = create_console_user(iam)

    findings = IAMNoMFACheck().run(context)

    assert [f.resource_id for f in findings] == [user_arn]
    assert findings[0].check_id == "AWS-IAM-002"
    assert findings[0].severity is Severity.HIGH


def test_no_mfa_passes_console_user_with_mfa(iam, context):
    create_console_user(iam)
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="test-device")[
        "VirtualMFADevice"
    ]["SerialNumber"]
    iam.enable_mfa_device(
        UserName=USER,
        SerialNumber=serial,
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    assert IAMNoMFACheck().run(context) == []


def test_no_mfa_passes_user_without_console_access(iam, context):
    iam.create_user(UserName=USER)

    assert IAMNoMFACheck().run(context) == []
