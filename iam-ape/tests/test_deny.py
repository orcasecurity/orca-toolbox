from typing import Any, Dict, Optional, Set, Tuple

from iam_ape.evaluator import should_deny
from iam_ape.helper_types import Action

action = "kms:CreateKey"
resource_wide = "arn:aws:kms:us-east-1:123456789012:*"
resource_narrow = "arn:aws:kms:us-east-1:123456789012:key/testing-key-1"
condition_1 = {"DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}}
condition_2 = {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}

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
                condition={
                    "DateLessThanEquals": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}
                },
                source=source,
            )
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
                condition={
                    "DateLessThanEquals": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}
                },
                source=source,
            )
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
                condition={
                    "DateLessThanEquals": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}
                },
                source=source,
            )
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
