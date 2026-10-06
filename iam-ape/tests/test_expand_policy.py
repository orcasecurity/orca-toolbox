from typing import Dict, Optional, Set, Tuple

import pytest

from iam_ape.expand_policy import PolicyExpander
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


def test_named_action_keeps_statement_resources_as_fallback() -> None:
    expanded = _expand(
        {
            "Effect": "Allow",
            "Action": ["ssm-guiconnect:StartConnection"],
            "Resource": [ec2_instances],
        }
    )
    assert _scopes(expanded, "ssm-guiconnect:StartConnection") == {
        (ec2_instances, None)
    }


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
