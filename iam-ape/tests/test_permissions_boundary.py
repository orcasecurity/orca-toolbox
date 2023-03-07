from typing import Dict, Set

from iam_ape.evaluator import apply_permission_boundary
from iam_ape.helper_types import Action, PermissionsContainer

action = "kms:CreateKey"
resource_wide = "arn:aws:kms:us-east-1:123456789012:key/testing-*"
resource_narrow = "arn:aws:kms:us-east-1:123456789012:key/testing-key-1"
resource_other = "arn:aws:kms:us-east-1:123456789012:key/prod-key-1"
condition_1 = {"DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}}
condition_2 = {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}

source = "test"

"""
def apply_permission_boundary(
    allow_actions: Dict[str, Set[Action]],
    permission_boundary: PermissionsContainer,
) -> Dict[str, Set[Action]]:

if action_tuple.resource and boundary_tuple.resource
"""


def _test_expected(
    allow: Dict[str, Set[Action]],
    boundary: PermissionsContainer,
    expected: Dict[str, Set[Action]],
    denied: bool = False,
) -> None:
    res, ineffective = apply_permission_boundary(allow, boundary)
    if denied:
        assert list(ineffective)[0].denied_by == f"Permission Boundary: {source}"
    assert res == expected


def default_action_tuple(r=None, nr=None, c=None) -> Dict[str, Set[Action]]:
    return {
        action: {
            Action(
                action=action, resource=r, not_resource=nr, condition=c, source=source
            )
        }
    }


def default_permissions_container(r=None, nr=None, c=None):
    return PermissionsContainer(
        allowed_permissions=default_action_tuple(r, nr, c), denied_permissions={}
    )


def test_allow_resource_gt_boundary_resource() -> None:
    allow = default_action_tuple(r=resource_wide)
    boundary = default_permissions_container(r=resource_narrow)
    expected = {
        action: {
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition=None,
                source=source,
            )
        }
    }
    _test_expected(allow, boundary, expected)


def test_allow_resource_lt_boundary_resource() -> None:
    allow = default_action_tuple(r=resource_narrow)
    boundary = default_permissions_container(r=resource_wide)
    expected = {
        action: {
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition=None,
                source=source,
            )
        }
    }
    _test_expected(allow, boundary, expected)


def test_allow_resource_not_in_boundary_resource() -> None:
    allow = default_action_tuple(r=resource_narrow)
    boundary = default_permissions_container(r=resource_other)
    expected: Dict[str, Set[Action]] = {}
    _test_expected(allow, boundary, expected, True)


def test_allow_resource_gt_boundary_notresource() -> None:
    allow = default_action_tuple(r=resource_wide)
    boundary = default_permissions_container(nr=resource_narrow)
    expected = {
        "kms:CreateKey": {
            Action(
                action="kms:CreateKey",
                resource="arn:aws:kms:us-east-1:123456789012:key/testing-*",
                not_resource="arn:aws:kms:us-east-1:123456789012:key/testing-key-1",
                condition=None,
                source="test",
            )
        }
    }
    _test_expected(allow, boundary, expected)


def test_allow_resource_lt_boundary_notresource() -> None:
    allow = default_action_tuple(r=resource_narrow)
    boundary = default_permissions_container(nr=resource_wide)
    expected: Dict[str, Set[Action]] = {}
    _test_expected(allow, boundary, expected, True)


def test_allow_resource_not_in_boundary_notresource() -> None:
    allow = default_action_tuple(r=resource_wide)
    boundary = default_permissions_container(nr=resource_other)
    expected = {
        "kms:CreateKey": {
            Action(
                action="kms:CreateKey",
                resource="arn:aws:kms:us-east-1:123456789012:key/testing-*",
                not_resource=None,
                condition=None,
                source="test",
            )
        }
    }
    _test_expected(allow, boundary, expected)


def test_allow_notresource_gt_boundary_resource() -> None:
    allow = default_action_tuple(nr=resource_wide)
    boundary = default_permissions_container(r=resource_narrow)
    expected: Dict[str, Set[Action]] = {}
    _test_expected(allow, boundary, expected, True)


def test_allow_notresource_lt_boundary_resource() -> None:
    allow = default_action_tuple(nr=resource_narrow)
    boundary = default_permissions_container(r=resource_wide)
    expected = {
        "kms:CreateKey": {
            Action(
                action="kms:CreateKey",
                resource="arn:aws:kms:us-east-1:123456789012:key/testing-*",
                not_resource="arn:aws:kms:us-east-1:123456789012:key/testing-key-1",
                condition=None,
                source="test",
            )
        }
    }
    _test_expected(allow, boundary, expected)


def test_allow_notresource_not_in_boundary_resource() -> None:
    allow = default_action_tuple(nr=resource_wide)
    boundary = default_permissions_container(r=resource_other)
    expected = {
        "kms:CreateKey": {
            Action(
                action="kms:CreateKey",
                resource="arn:aws:kms:us-east-1:123456789012:key/prod-key-1",
                not_resource=None,
                condition=None,
                source="test",
            )
        }
    }
    _test_expected(allow, boundary, expected)


def test_allow_notresource_gt_boundary_notresource() -> None:
    allow = default_action_tuple(nr=resource_wide)
    boundary = default_permissions_container(nr=resource_narrow)
    expected = {
        "kms:CreateKey": {
            Action(
                action="kms:CreateKey",
                resource=None,
                not_resource="arn:aws:kms:us-east-1:123456789012:key/testing-*",
                condition=None,
                source="test",
            )
        }
    }
    _test_expected(allow, boundary, expected)


def test_allow_notresource_lt_boundary_notresource() -> None:
    allow = default_action_tuple(nr=resource_narrow)
    boundary = default_permissions_container(nr=resource_wide)
    expected = {
        "kms:CreateKey": {
            Action(
                action="kms:CreateKey",
                resource=None,
                not_resource="arn:aws:kms:us-east-1:123456789012:key/testing-*",
                condition=None,
                source="test",
            )
        }
    }
    _test_expected(allow, boundary, expected)


def test_allow_notresource_not_in_boundary_notresource() -> None:
    allow = default_action_tuple(nr=resource_wide)
    boundary = default_permissions_container(nr=resource_other)
    expected = {
        "kms:CreateKey": {
            Action(
                action="kms:CreateKey",
                resource=None,
                not_resource="arn:aws:kms:us-east-1:123456789012:key/prod-key-1",
                condition=None,
                source="test",
            ),
            Action(
                action="kms:CreateKey",
                resource=None,
                not_resource="arn:aws:kms:us-east-1:123456789012:key/testing-*",
                condition=None,
                source="test",
            ),
        }
    }
    _test_expected(allow, boundary, expected)
