import json
import os

from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.helper_types import EntityType

expected_result = {
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["ec2:*"],
            "Resource": ["*"],
            "Condition": {
                "StringEquals": {"aws:RequestedRegion": ["us-east-1"]},
                "Bool": {
                    "aws:MultiFactorAuthPresent": ["true"],
                    "aws:ViaAWSService": ["true"],
                },
            },
        },
        {
            "Effect": "Allow",
            "Action": [
                "organizations:DescribeAccount",
                "organizations:DescribeOrganization",
                "organizations:DescribeOrganizationalUnit",
                "organizations:DescribePolicy",
                "organizations:ListChildren",
                "organizations:ListParents",
                "organizations:ListPolicies",
                "organizations:ListPoliciesForTarget",
                "organizations:ListRoots",
                "organizations:ListTargetsForPolicy",
                "es:*",
            ],
            "Resource": ["*"],
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": ["true"],
                    "aws:ViaAWSService": ["true"],
                }
            },
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [
                "arn:aws:s3:::cf-templates-hrlp5hbiotb8-us-east-1",
                "arn:aws:s3:::cf-templates-hrlp5hbiotb8-us-east-1/*",
            ],
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": ["true"],
                    "aws:ViaAWSService": ["true"],
                }
            },
        },
    ]
}


def test_e2e() -> None:
    with open(os.path.join(os.path.dirname(__file__), "test_data.json")) as f:
        data = json.load(f)
    auth_details = AuthorizationDetails(data)

    assert len(auth_details.User) == 1
    assert len(auth_details.Group) == 3
    assert len(auth_details.Role) == 2
    assert len(auth_details.Policy) == 6

    evaluator = EffectivePolicyEvaluator(auth_details)
    res = evaluator.evaluate(
        arn="arn:aws:iam::123456789012:user/TestUser1", entity_type=EntityType.user
    )

    assert len(res.allowed_permissions) > 600
    assert len(res.denied_permissions) > 13000
    assert len(res.ineffective_permissions) > 150

    minimized_policy = evaluator.policy_expander.shrink_policy(res.allowed_permissions)
    assert len(minimized_policy["Statement"]) == 3
    assert all(
        [
            statement in minimized_policy["Statement"]
            for statement in expected_result["Statement"]
        ]
    )

    json_report = evaluator.create_json_report(res)
    assert sum(
        [
            len(y)
            for x in json_report["allowed_permissions"].values()
            for v in x.values()
            for y in v.values()
        ]
    ) == sum([len(x) for x in res.allowed_permissions.values()])
    assert sum(
        [
            len(y)
            for x in json_report["denied_permissions"].values()
            for v in x.values()
            for y in v.values()
        ]
    ) == sum([len(x) for x in res.denied_permissions.values()])
    assert sum(
        [
            len(y)
            for x in json_report["ineffective_permissions"].values()
            for v in x.values()
            for y in v.values()
        ]
    ) == len(res.ineffective_permissions)
