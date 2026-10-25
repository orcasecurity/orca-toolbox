"""Allows after identity-policy denies, checked request by request against a direct evaluation of the policy."""
import json
from typing import Any, Dict, List

import pytest

from iam_ape.access import apply_denies
from iam_ape.helper_classes import Action
from tests.fixtures import evaluate_role, statement
from tests.semantics import actions_allow, condition_keys, policy_allows, probes

GET = "s3:GetObject"
OBJECTS = [
    f"arn:aws:s3:::{key}"
    for key in [
        "a/x",
        "b/x",
        "corp/x",
        "other/x",
        "x-prod/k",
        "team-prod/k",
        "team-x-prod/k",
        "secret/x",
        "secret/public/x",
    ]
]
CANDIDATES: Dict[str, List[Any]] = {
    "aws:SourceVpc": [None, "vpc-1", "vpc-2"],
    "aws:SourceAccount": [None, "111111111111", "222222222222"],
    "aws:ViaAWSService": [None, "true", "false"],
    "aws:MultiFactorAuthPresent": [None, "true", "false"],
    "aws:MultiFactorAuthAge": [None, "1", "7", "20"],
    "aws:RequestedRegion": [None, "us-east-1", "eu-west-1", "us-west-2"],
    "aws:TokenIssueTime": [None, "2018-01-01T00:00:00Z", "2019-01-01T00:00:00Z"],
    "aws:SourceIp": [None, "203.0.113.5", "198.51.100.5"],
    "aws:TagKeys": [None, ["secret"], ["public"], ["public", "secret"]],
}


def allow(**kwargs: Any) -> Dict[str, Any]:
    return statement("Allow", GET, **kwargs)


def deny(**kwargs: Any) -> Dict[str, Any]:
    return statement("Deny", GET, **kwargs)


def mismatches(statements: List[Dict[str, Any]], boundary: Any = None) -> List[Any]:
    """Requests iam-ape decides differently from AWS."""
    allowed = evaluate_role(statements, boundary).allowed_permissions.get(GET, set())
    every = statements + (boundary or [])
    keys = {k: CANDIDATES[k] for k in condition_keys(every)}
    return [
        (resource, context)
        for resource, context in probes(OBJECTS, keys)
        if actions_allow(allowed, GET, resource, context)
        != (
            policy_allows(statements, GET, resource, context)
            and (boundary is None or policy_allows(boundary, GET, resource, context))
        )
    ]


CASES = {
    "deny narrower than allow": [
        allow(resource="arn:aws:s3:::*"),
        deny(resource="arn:aws:s3:::a/*"),
    ],
    "deny wider than allow": [
        allow(resource="arn:aws:s3:::a/*"),
        deny(resource="arn:aws:s3:::*"),
    ],
    "conditional deny narrower than allow": [
        allow(resource="arn:aws:s3:::*"),
        deny(
            resource="arn:aws:s3:::a/*",
            condition={
                "DateGreaterThan": {"aws:TokenIssueTime": "2018-06-01T00:00:00Z"}
            },
        ),
    ],
    "conditional allow, conditional deny": [
        allow(
            resource="arn:aws:s3:::*",
            condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
        ),
        deny(
            resource="arn:aws:s3:::a/*",
            condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
        ),
    ],
    "deny NotResource narrower than allow": [
        allow(resource="arn:aws:s3:::*"),
        deny(not_resource="arn:aws:s3:::a/*"),
    ],
    "conditional deny with NotResource": [
        allow(resource="arn:aws:s3:::*"),
        deny(
            not_resource="arn:aws:s3:::a/*",
            condition={"Bool": {"aws:ViaAWSService": "false"}},
        ),
    ],
    "allow NotResource, deny NotResource": [
        allow(not_resource="arn:aws:s3:::b/*"),
        deny(not_resource=["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"]),
    ],
    "allow NotResource, conditional deny NotResource": [
        allow(not_resource="arn:aws:s3:::secret/*"),
        deny(
            not_resource="arn:aws:s3:::a/*",
            condition={"StringNotEquals": {"aws:SourceVpc": "vpc-1"}},
        ),
    ],
    "P1 perimeter deny": [
        allow(resource="arn:aws:s3:::other/*"),
        deny(not_resource="arn:aws:s3:::corp/*"),
    ],
    "P2 NotResource allow minus a Resource deny": [
        allow(not_resource="arn:aws:s3:::b/*"),
        deny(resource="arn:aws:s3:::a/*"),
    ],
    "P3 two NotResource allows": [
        allow(not_resource="arn:aws:s3:::a/*"),
        allow(not_resource="arn:aws:s3:::b/*"),
    ],
    "P4 NotResource allow plus a Resource allow": [
        allow(not_resource="arn:aws:s3:::secret/*"),
        allow(resource="arn:aws:s3:::secret/public/*"),
    ],
    "P5 deny on two keys": [
        allow(),
        deny(
            condition={
                "StringNotEquals": {"aws:SourceVpc": "vpc-1"},
                "Bool": {"aws:ViaAWSService": "false"},
            }
        ),
    ],
    "P6 one operator on two keys": [
        allow(),
        deny(
            condition={
                "StringNotEquals": {
                    "aws:SourceVpc": "vpc-1",
                    "aws:SourceAccount": "222222222222",
                }
            }
        ),
    ],
    "P7 ForAnyValue deny": [
        allow(),
        deny(condition={"ForAnyValue:StringEquals": {"aws:TagKeys": ["secret"]}}),
    ],
    "ForAllValues deny": [
        allow(),
        deny(condition={"ForAllValues:StringEquals": {"aws:TagKeys": ["secret"]}}),
    ],
    "P8 deny narrows an allowed region": [
        allow(condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}}),
        deny(
            condition={
                "StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "eu-west-1"]}
            }
        ),
    ],
    "P9 two region denies": [
        allow(),
        deny(condition={"StringEquals": {"aws:RequestedRegion": "us-west-2"}}),
        deny(condition={"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}),
    ],
    "two resource denies": [
        allow(),
        deny(resource="arn:aws:s3:::a/*"),
        deny(resource="arn:aws:s3:::b/*"),
    ],
    "allowed values minus denied ones": [
        allow(
            condition={
                "StringEquals": {"aws:RequestedRegion": ["us-east-1", "eu-west-1"]}
            }
        ),
        deny(condition={"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}),
    ],
    "P12 partial overlap": [
        allow(resource="arn:aws:s3:::*-prod/*"),
        deny(not_resource="arn:aws:s3:::team-*/*"),
    ],
    "P18 deny StringEqualsIfExists": [
        allow(),
        deny(condition={"StringEqualsIfExists": {"aws:SourceVpc": "vpc-2"}}),
    ],
    "deny StringNotEqualsIfExists": [
        allow(),
        deny(condition={"StringNotEqualsIfExists": {"aws:SourceVpc": "vpc-1"}}),
    ],
    "P19 deny without MFA": [
        allow(),
        deny(condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}}),
    ],
    "deny BoolIfExists": [
        allow(),
        deny(condition={"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}),
    ],
    "deny Null": [
        allow(),
        deny(condition={"Null": {"aws:SourceVpc": "true"}}),
    ],
    "deny NumericGreaterThan": [
        allow(condition={"NumericLessThan": {"aws:MultiFactorAuthAge": "10"}}),
        deny(condition={"NumericGreaterThan": {"aws:MultiFactorAuthAge": "5"}}),
    ],
    "P36 deny old sessions": [
        allow(),
        deny(
            condition={"DateLessThan": {"aws:TokenIssueTime": "2018-05-23T14:01:36Z"}}
        ),
    ],
    "deny NotIpAddress": [
        allow(),
        deny(condition={"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}}),
    ],
    "deny NotAction": [
        allow(),
        statement("Deny", not_action="s3:PutObject", resource="arn:aws:s3:::a/*"),
    ],
}


@pytest.mark.parametrize("statements", CASES.values(), ids=CASES.keys())
def test_matches_direct_evaluation(statements: List[Dict[str, Any]]) -> None:
    assert mismatches(statements) == []


def test_fully_denied_allow_is_ineffective_with_the_deny_as_its_reason() -> None:
    container = evaluate_role(
        [allow(resource="arn:aws:s3:::a/*"), deny(resource="arn:aws:s3:::*")]
    )
    assert GET not in container.allowed_permissions
    assert {
        (a.action, a.denied_by)
        for a in container.ineffective_permissions
        if a.action == GET
    } == {(GET, "inline/1")}


def test_deny_on_another_resource_leaves_the_allow_as_it_is() -> None:
    granted = Action(GET, "arn:aws:s3:::a/*", (), None, "allow")
    denied = Action(GET, "arn:aws:s3:::b/*", (), None, "deny")
    assert apply_denies(granted, [denied]) == (frozenset({granted}), None)


def test_unconditional_deny_narrower_than_allow_becomes_an_exclusion() -> None:
    granted = Action(GET, None, (), None, "allow")
    denied = Action(GET, "arn:aws:s3:::a/*", (), None, "deny")
    assert apply_denies(granted, [denied]) == (
        frozenset({Action(GET, None, ("arn:aws:s3:::a/*",), None, "allow")}),
        None,
    )


def test_spot_only_launch_splits_the_allow() -> None:
    # Shape of AWSEC2SpotServiceRolePolicy: instances may only be launched as spot
    instances = "arn:aws:ec2:*:*:instance/*"
    allowed = evaluate_role(
        [
            statement(action="ec2:RunInstances"),
            statement(
                "Deny",
                "ec2:RunInstances",
                resource=instances,
                condition={"StringNotEquals": {"ec2:InstanceMarketType": "spot"}},
            ),
        ]
    ).allowed_permissions["ec2:RunInstances"]
    assert {
        (a.resource, a.not_resources, json.dumps(a.condition)) for a in allowed
    } == {
        (None, (instances,), "null"),
        (instances, (), '{"StringEquals": {"ec2:InstanceMarketType": ["spot"]}}'),
    }


def test_deny_that_cant_be_negated_keeps_the_allow() -> None:
    # BinaryEquals has no negation: the allow stays as it was (more than AWS allows, never less)
    allowed = evaluate_role(
        [allow(), deny(condition={"BinaryEquals": {"aws:SourceVpc": "QmluYXJ5"}})]
    ).allowed_permissions[GET]
    assert {(a.resource, a.condition) for a in allowed} == {("*", None)}
