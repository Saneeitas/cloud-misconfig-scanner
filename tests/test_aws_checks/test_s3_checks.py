"""S3 checks, each tested against compliant and non-compliant buckets."""

import json

import pytest

from scanner.checks.aws.s3_encryption import S3EncryptionCheck
from scanner.checks.aws.s3_logging import S3LoggingCheck
from scanner.checks.aws.s3_public_policy import S3PublicPolicyCheck
from scanner.checks.aws.s3_versioning import S3VersioningCheck
from scanner.models import Severity

BUCKET = "test-bucket"
BUCKET_ARN = f"arn:aws:s3:::{BUCKET}"
READER_ROLE = "arn:aws:iam::123456789012:role/reader"


def statement(principal, effect="Allow", **extra):
    return {
        "Effect": effect,
        "Principal": principal,
        "Action": "s3:GetObject",
        "Resource": f"{BUCKET_ARN}/*",
        **extra,
    }


def put_policy(s3, statements):
    s3.create_bucket(Bucket=BUCKET)
    s3.put_bucket_policy(
        Bucket=BUCKET,
        Policy=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


@pytest.mark.parametrize(
    "statements",
    [
        [statement("*")],
        [statement({"AWS": "*"})],
        [statement({"AWS": [READER_ROLE, "*"]})],
        statement("*"),  # AWS allows a single statement without a list
        [statement(READER_ROLE), statement("*")],
        [statement("*", Condition={"Bool": {"aws:SecureTransport": "true"}})],
    ],
    ids=["star", "aws-star", "star-in-list", "single-statement", "second-statement", "conditional"],
)
def test_public_policy_flags_public_allow(s3, context, statements):
    put_policy(s3, statements)

    findings = S3PublicPolicyCheck().run(context)

    assert [f.resource_id for f in findings] == [BUCKET_ARN]
    assert findings[0].check_id == "AWS-S3-001"
    assert findings[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    "statements",
    [
        [statement({"AWS": READER_ROLE})],
        [
            statement(
                "*",
                effect="Deny",
                Condition={"Bool": {"aws:SecureTransport": "false"}},
            )
        ],
    ],
    ids=["specific-principal", "enforce-tls-deny"],
)
def test_public_policy_passes_non_public_policy(s3, context, statements):
    put_policy(s3, statements)

    assert S3PublicPolicyCheck().run(context) == []


def test_public_policy_passes_bucket_without_policy(s3, context):
    s3.create_bucket(Bucket=BUCKET)

    assert S3PublicPolicyCheck().run(context) == []


def test_versioning_flags_bucket_never_enabled(s3, context):
    s3.create_bucket(Bucket=BUCKET)

    findings = S3VersioningCheck().run(context)

    assert [(f.check_id, f.resource_id) for f in findings] == [("AWS-S3-002", BUCKET_ARN)]


def test_versioning_flags_suspended_bucket(s3, context):
    s3.create_bucket(Bucket=BUCKET)
    s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Suspended"})

    assert len(S3VersioningCheck().run(context)) == 1


def test_versioning_passes_enabled_bucket(s3, context):
    s3.create_bucket(Bucket=BUCKET)
    s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})

    assert S3VersioningCheck().run(context) == []


def test_logging_flags_bucket_without_logging(s3, context):
    s3.create_bucket(Bucket=BUCKET)

    findings = S3LoggingCheck().run(context)

    assert [(f.check_id, f.resource_id) for f in findings] == [("AWS-S3-003", BUCKET_ARN)]


def test_logging_passes_bucket_with_logging(s3, context):
    s3.create_bucket(Bucket=BUCKET)
    s3.create_bucket(Bucket="log-bucket")
    s3.put_bucket_acl(
        Bucket="log-bucket",
        GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
    )
    s3.put_bucket_logging(
        Bucket=BUCKET,
        BucketLoggingStatus={
            "LoggingEnabled": {"TargetBucket": "log-bucket", "TargetPrefix": "logs/"}
        },
    )

    flagged = [f.resource_id for f in S3LoggingCheck().run(context)]

    assert BUCKET_ARN not in flagged


def set_encryption(s3, algorithm):
    s3.put_bucket_encryption(
        Bucket=BUCKET,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algorithm}}]
        },
    )


def test_encryption_flags_sse_s3_bucket(s3, context):
    s3.create_bucket(Bucket=BUCKET)
    set_encryption(s3, "AES256")

    findings = S3EncryptionCheck().run(context)

    assert [(f.check_id, f.resource_id) for f in findings] == [("AWS-S3-004", BUCKET_ARN)]


def test_encryption_passes_sse_kms_bucket(s3, context):
    s3.create_bucket(Bucket=BUCKET)
    set_encryption(s3, "aws:kms")

    assert S3EncryptionCheck().run(context) == []
