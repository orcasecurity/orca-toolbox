from typing import Dict, List, Optional, Set, Tuple

import pytest

from iam_ape.expand_policy import (
    PolicyExpander,
    minimize_actions,
    shorten_to_leading_word,
)
from iam_ape.helper_classes import Action, PolicyWithSource
from iam_ape.helper_functions import normalize_policy
from iam_ape.helper_types import AwsPolicyStatementType

source = "test"
ec2_instances = "arn:aws:ec2:*:*:instance/*"
s3_objects = "arn:aws:s3:::example-bucket/*"

expander = PolicyExpander()


def _expand(statement: AwsPolicyStatementType) -> Dict[str, Set[Action]]:
    policy = normalize_policy({"Version": "2012-10-17", "Statement": [statement]})
    return expander.expand_policies(
        [PolicyWithSource(source, policy)]
    ).allowed_permissions


def _scopes(
    expanded: Dict[str, Set[Action]], action: str
) -> Set[Tuple[Optional[str], Optional[str]]]:
    return {(a.resource, a.not_resource) for a in expanded.get(action, set())}


@pytest.mark.parametrize(
    "action, resource",
    [
        ("ssm:SendCommand", ec2_instances),
        ("ssm:StartSession", "arn:aws:ecs:*:*:task/*"),
        ("ssmmessages:OpenDataChannel", "arn:aws:ssm:*:*:session/*"),
        ("ec2-instance-connect:SendSSHPublicKey", ec2_instances),
        ("sts:AssumeRole", "arn:aws:iam::123456789012:role/example-role"),
        ("rds-data:ExecuteStatement", "arn:aws:rds:us-east-1:123456789012:cluster:db"),
        (
            "redshift-data:ExecuteStatement",
            "arn:aws:redshift:us-east-1:123456789012:cluster:dw",
        ),
        (
            "redshift-data:ExecuteStatement",
            "arn:aws:redshift-serverless:us-east-1:123456789012:workgroup/wg",
        ),
    ],
)
def test_cross_service_resource_is_kept(action: str, resource: str) -> None:
    expanded = _expand(
        {"Effect": "Allow", "Action": [action], "Resource": [resource, s3_objects]}
    )
    assert _scopes(expanded, action) == {(resource, None)}


def test_unrelated_cross_service_pair_is_dropped() -> None:
    expanded = _expand(
        {
            "Effect": "Allow",
            "Action": ["ssm:SendCommand", "s3:GetObject"],
            "Resource": [ec2_instances, s3_objects],
        }
    )
    assert _scopes(expanded, "s3:GetObject") == {(s3_objects, None)}
    assert _scopes(expanded, "ssm:SendCommand") == {(ec2_instances, None)}


def test_named_action_does_not_take_resources_of_another_service() -> None:
    expanded = _expand(
        {
            "Effect": "Allow",
            "Action": ["xray:GetSamplingTargets"],
            "Resource": ["arn:aws:states:us-west-2:123456789012:*"],
        }
    )
    assert "xray:GetSamplingTargets" not in expanded


def test_wildcard_action_does_not_spread_to_other_services() -> None:
    expanded = _expand({"Effect": "Allow", "Action": ["*"], "Resource": [s3_objects]})
    assert expanded
    assert {key.split(":")[0] for key in expanded} == {"s3"}


@pytest.mark.parametrize(
    "resource",
    [
        "arn:aws-us-gov:s3:::example-bucket/*",
        "arn:aws-cn:s3:::example-bucket/*",
        "arn:aws-iso-b:s3:::example-bucket/*",
    ],
)
def test_non_commercial_partition_is_kept(resource: str) -> None:
    expanded = _expand(
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [resource, s3_objects],
        }
    )
    assert _scopes(expanded, "s3:GetObject") == {(resource, None), (s3_objects, None)}


@pytest.mark.parametrize(
    "action, resource",
    [
        ("glue:GetDatabase", "arn:*:glue:*:*:catalog"),
        ("ec2:RunInstances", "arn:*:ec2:*:*:instance/*"),
    ],
)
def test_partition_wildcard_is_kept(action: str, resource: str) -> None:
    expanded = _expand(
        {"Effect": "Allow", "Action": [action], "Resource": [resource, s3_objects]}
    )
    assert _scopes(expanded, action) == {(resource, None)}


def test_service_wildcard_is_kept_for_every_action() -> None:
    resource = "arn:aws:*:*:*:*"
    expanded = _expand(
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "kms:Decrypt"],
            "Resource": [resource, s3_objects],
        }
    )
    assert _scopes(expanded, "s3:GetObject") == {(resource, None), (s3_objects, None)}
    assert _scopes(expanded, "kms:Decrypt") == {(resource, None)}


def test_notresource_of_other_service_keeps_action() -> None:
    not_resource = "arn:aws:s3:::example-bucket"
    expanded = _expand(
        {"Effect": "Allow", "Action": ["*"], "NotResource": [not_resource]}
    )
    assert _scopes(expanded, "ec2:RunInstances") == {(None, not_resource)}


def _reexpand(minimized: List[str]) -> Set[str]:
    return set(_expand({"Effect": "Allow", "Action": minimized, "Resource": ["*"]}))


@pytest.mark.parametrize(
    "service, actions",
    [
        ("kms", ["ReEncryptFrom", "ReEncryptTo", "TagResource"]),
        ("apigateway", ["GET", "PATCH"]),
        (
            "lightsail",
            ["SetIpAddressType", "SetResourceAccessForBucket", "TagResource"],
        ),
    ],
)
def test_minimize_keeps_actions_whose_wildcard_matches_more(
    service: str, actions: List[str]
) -> None:
    minimized = minimize_actions(service, actions, expander.all_iam_actions[service])
    assert _reexpand(minimized) == {f"{service}:{action}" for action in actions}


def test_minimize_round_trips_every_leading_word_group() -> None:
    for service, service_actions in expander.all_iam_actions.items():
        all_actions = frozenset(service_actions.keys())
        for group in shorten_to_leading_word(all_actions).values():
            actions = sorted(group | {min(all_actions - group, default=min(group))})
            minimized = minimize_actions(service, actions, service_actions)
            assert _reexpand(minimized) == {f"{service}:{a}" for a in actions}
