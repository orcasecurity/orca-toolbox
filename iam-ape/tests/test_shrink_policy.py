from typing import Any, Dict, List

from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.helper_types import EntityType

ROLE = "arn:aws:iam::111111111111:role/r"


def _shrunk(statements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    role = {
        "Arn": ROLE,
        "RoleName": "r",
        "RoleId": "AROAR",
        "Path": "/",
        "AttachedManagedPolicies": [],
        "InstanceProfileList": [],
        "Tags": [],
        "RolePolicyList": [
            {
                "PolicyName": "p",
                "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
            }
        ],
    }
    evaluator = EffectivePolicyEvaluator(
        AuthorizationDetails(
            {
                "RoleDetailList": [role],
                "UserDetailList": [],
                "GroupDetailList": [],
                "Policies": [],
            }
        )
    )
    allowed = evaluator.evaluate(ROLE, EntityType.role).allowed_permissions
    return [
        {k: v for k, v in statement.items() if k != "Effect"}
        for statement in evaluator.policy_expander.shrink_policy(allowed)["Statement"]
    ]


def test_two_not_resource_allows_stay_apart() -> None:
    # "all but a" or "all but b" is everything; one statement "all but a and b" would lose both buckets
    shrunk = _shrunk(
        [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::a/*",
            },
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::b/*",
            },
        ]
    )
    assert sorted(s["NotResource"][0] for s in shrunk) == [
        "arn:aws:s3:::a/*",
        "arn:aws:s3:::b/*",
    ]
    assert all(len(s["NotResource"]) == 1 and "Resource" not in s for s in shrunk)


def test_not_resource_allow_is_not_merged_into_a_resource_allow() -> None:
    shrunk = _shrunk(
        [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::secret/*",
            },
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::secret/public/*",
            },
        ]
    )
    assert sorted(shrunk, key=str) == sorted(
        [
            {"Action": ["s3:GetObject"], "NotResource": ["arn:aws:s3:::secret/*"]},
            {"Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::secret/public/*"]},
        ],
        key=str,
    )


def test_resource_allows_still_share_one_statement() -> None:
    shrunk = _shrunk(
        [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::a/*",
            },
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            },
        ]
    )
    assert shrunk == [
        {
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"],
        }
    ]
