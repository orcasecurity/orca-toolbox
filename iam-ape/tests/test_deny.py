from typing import Any, Dict, Optional, Set, Tuple

from iam_ape.evaluator import explicitly_deny, should_deny
from iam_ape.expand_policy import PolicyExpander
from iam_ape.helper_classes import Action, PolicyWithSource
from iam_ape.helper_functions import normalize_policy
from iam_ape.helper_types import AwsPolicyStatementType

action = "kms:CreateKey"
resource_wide = "arn:aws:kms:us-east-1:123456789012:*"
resource_narrow = "arn:aws:kms:us-east-1:123456789012:key/testing-key-1"
condition_1 = {"DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}}
condition_2 = {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}
ec2_instances = "arn:aws:ec2:*:*:instance/*"

source = "test"


def _test_expected(
    allow: Action, deny: Action, expected: Tuple[bool, Set[Action], Optional[str]]
) -> None:
    res = should_deny(allow, {action: {deny}})
    assert res == expected


def default_action_tuple(
    r: Optional[str] = None,
    nr: Optional[str] = None,
    c: Optional[Dict[str, Any]] = None,
) -> Action:
    return Action(
        action=action, resource=r, not_resource=nr, condition=c, source=source
    )


def test_allow_resource_gt_deny_resource() -> None:
    a = default_action_tuple(r=resource_wide)
    d = default_action_tuple(r=resource_narrow)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_wide,
                not_resource=resource_narrow,
                condition=None,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_resource_lt_deny_resource() -> None:
    a = default_action_tuple(r=resource_narrow)
    d = default_action_tuple(r=resource_wide)
    expected = (True, set(), source)  # type: ignore
    _test_expected(a, d, expected)


def test_allow_resource_gt_deny_resource_with_condition() -> None:
    a = default_action_tuple(r=resource_wide)
    d = default_action_tuple(r=resource_narrow, c=condition_1)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_wide,
                not_resource=resource_narrow,
                condition=None,
                source=source,
            ),
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition={
                    "DateLessThanEquals": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}
                },
                source=source,
            ),
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_resource_lt_deny_resource_with_condition() -> None:
    a = default_action_tuple(r=resource_narrow)
    d = default_action_tuple(r=resource_wide, c=condition_1)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition={
                    "DateLessThanEquals": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}
                },
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_resource_with_condition_gt_deny_resource_with_condition() -> None:
    a = default_action_tuple(r=resource_wide, c=condition_1)
    d = default_action_tuple(r=resource_narrow, c=condition_2)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_wide,
                not_resource=resource_narrow,
                condition=condition_1,
                source=source,
            ),
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition={
                    "DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"},
                    "NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"},
                },
                source=source,
            ),
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_resource_with_condition_lt_deny_resource_with_condition() -> None:
    a = default_action_tuple(r=resource_narrow, c=condition_1)
    d = default_action_tuple(r=resource_wide, c=condition_2)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition={
                    "DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"},
                    "NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"},
                },
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_resource_gt_deny_notresource() -> None:
    a = default_action_tuple(r=resource_wide)
    d = default_action_tuple(nr=resource_narrow)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition=None,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_resource_lt_deny_notresource() -> None:
    a = default_action_tuple(r=resource_narrow)
    d = default_action_tuple(nr=resource_wide)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition=None,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_resource_gt_deny_notresource_with_condition() -> None:
    a = default_action_tuple(r=resource_wide)
    d = default_action_tuple(nr=resource_narrow, c=condition_1)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition=None,
                source=source,
            ),
            Action(
                action=action,
                resource=resource_wide,
                not_resource=resource_narrow,
                condition={
                    "DateLessThanEquals": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}
                },
                source=source,
            ),
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_resource_lt_deny_notresource_with_condition() -> None:
    a = default_action_tuple(r=resource_narrow)
    d = default_action_tuple(nr=resource_wide, c=condition_1)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition=None,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_resource_with_condition_gt_deny_notresource_with_condition() -> None:
    a = default_action_tuple(r=resource_wide, c=condition_1)
    d = default_action_tuple(nr=resource_narrow, c=condition_2)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition=condition_1,
                source=source,
            ),
            Action(
                action=action,
                resource=resource_wide,
                not_resource=resource_narrow,
                condition={
                    "DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"},
                    "NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"},
                },
                source=source,
            ),
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_resource_with_condition_lt_deny_notresource_with_condition() -> None:
    a = default_action_tuple(r=resource_narrow, c=condition_1)
    d = default_action_tuple(nr=resource_wide, c=condition_2)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=resource_narrow,
                not_resource=None,
                condition=condition_1,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_gt_deny_resource() -> None:
    a = default_action_tuple(nr=resource_wide)
    d = default_action_tuple(r=resource_narrow)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition=None,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_lt_deny_resource() -> None:
    a = default_action_tuple(nr=resource_narrow)
    d = default_action_tuple(r=resource_wide)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition=None,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_gt_deny_resource_with_condition() -> None:
    a = default_action_tuple(nr=resource_wide)
    d = default_action_tuple(r=resource_narrow, c=condition_1)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition=None,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_lt_deny_resource_with_condition() -> None:
    a = default_action_tuple(nr=resource_narrow)
    d = default_action_tuple(r=resource_wide, c=condition_1)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition=None,
                source=source,
            ),
            Action(
                action=action,
                resource=resource_wide,
                not_resource=resource_narrow,
                condition={
                    "DateLessThanEquals": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}
                },
                source=source,
            ),
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_with_condition_gt_deny_resource_with_condition() -> None:
    a = default_action_tuple(nr=resource_wide, c=condition_1)
    d = default_action_tuple(r=resource_narrow, c=condition_2)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition=condition_1,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_with_condition_lt_deny_resource_with_condition() -> None:
    a = default_action_tuple(nr=resource_narrow, c=condition_1)
    d = default_action_tuple(r=resource_wide, c=condition_2)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition=condition_1,
                source=source,
            ),
            Action(
                action=action,
                resource=resource_wide,
                not_resource=resource_narrow,
                condition={
                    "DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"},
                    "NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"},
                },
                source=source,
            ),
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_gt_deny_notresource() -> None:
    a = default_action_tuple(nr=resource_wide)
    d = default_action_tuple(nr=resource_narrow)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition=None,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_lt_deny_notresource() -> None:
    a = default_action_tuple(nr=resource_narrow)
    d = default_action_tuple(nr=resource_wide)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition=None,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_gt_deny_notresource_with_condition() -> None:
    a = default_action_tuple(nr=resource_wide)
    d = default_action_tuple(nr=resource_narrow, c=condition_1)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition=None,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_lt_deny_notresource_with_condition() -> None:
    a = default_action_tuple(nr=resource_narrow)
    d = default_action_tuple(nr=resource_wide, c=condition_1)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition={
                    "DateLessThanEquals": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}
                },
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_with_condition_gt_deny_notresource_with_condition() -> None:
    a = default_action_tuple(nr=resource_wide, c=condition_1)
    d = default_action_tuple(nr=resource_narrow, c=condition_2)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition=condition_1,
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def test_allow_notresource_with_condition_lt_deny_notresource_with_condition() -> None:
    a = default_action_tuple(nr=resource_narrow, c=condition_1)
    d = default_action_tuple(nr=resource_wide, c=condition_2)
    expected = (
        False,
        {
            Action(
                action=action,
                resource=None,
                not_resource=resource_wide,
                condition={
                    "DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"},
                    "NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"},
                },
                source=source,
            )
        },
        None,
    )
    _test_expected(a, d, expected)


def _spot_policy_permissions(deny_condition: Optional[Dict[str, Any]]) -> Set[Action]:
    deny_statement: AwsPolicyStatementType = {
        "Effect": "Deny",
        "Action": ["ec2:RunInstances"],
        "Resource": [ec2_instances],
    }
    if deny_condition:
        deny_statement["Condition"] = deny_condition
    policy = normalize_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["ec2:RunInstances"], "Resource": ["*"]},
                deny_statement,
            ],
        }
    )
    permissions = PolicyExpander().expand_policies([PolicyWithSource(source, policy)])
    allowed, _ = explicitly_deny(permissions)
    return allowed["ec2:RunInstances"]


def test_conditional_deny_narrower_than_allow_splits_the_allow() -> None:
    # Shape of AWSEC2SpotServiceRolePolicy: instances may only be launched as spot
    allowed = _spot_policy_permissions(
        {"StringNotEquals": {"ec2:InstanceMarketType": "spot"}}
    )
    assert allowed == {
        Action(
            action="ec2:RunInstances",
            resource=None,
            not_resource=ec2_instances,
            condition=None,
            source=f"{source}/0",
        ),
        Action(
            action="ec2:RunInstances",
            resource=ec2_instances,
            not_resource=None,
            condition={"StringEquals": {"ec2:InstanceMarketType": ["spot"]}},
            source=f"{source}/0",
        ),
    }


def test_unconditional_deny_narrower_than_allow_excludes_the_denied_resource() -> None:
    allowed = _spot_policy_permissions(None)
    assert allowed == {
        Action(
            action="ec2:RunInstances",
            resource=None,
            not_resource=ec2_instances,
            condition=None,
            source=f"{source}/0",
        )
    }


def test_conditional_deny_on_disjoint_resource_leaves_allow_unchanged() -> None:
    a = default_action_tuple(r="arn:aws:kms:us-east-1:123456789012:key/prod-key-1")
    d = default_action_tuple(
        r="arn:aws:kms:us-east-1:123456789012:key/testing-*", c=condition_1
    )
    _test_expected(a, d, (False, {a}, None))
