"""Allows inside a permissions boundary, checked request by request against a direct evaluation."""
from typing import Any, Dict, List, Tuple

import pytest

from tests.fixtures import BOUNDARY, ROLE, evaluate, evaluate_role, role, statement
from tests.test_deny import GET, allow, deny, mismatches

WIDE = "arn:aws:s3:::*"
NARROW = "arn:aws:s3:::a/*"
OTHER = "arn:aws:s3:::b/*"

CASES: Dict[str, Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]] = {
    "allow wider than boundary": ([allow(resource=WIDE)], [allow(resource=NARROW)]),
    "allow narrower than boundary": ([allow(resource=NARROW)], [allow(resource=WIDE)]),
    "allow outside boundary": ([allow(resource=NARROW)], [allow(resource=OTHER)]),
    "allow wider than boundary NotResource": (
        [allow(resource=WIDE)],
        [allow(not_resource=NARROW)],
    ),
    "allow inside boundary NotResource": (
        [allow(resource=NARROW)],
        [allow(not_resource=OTHER)],
    ),
    "allow excluded by boundary NotResource": (
        [allow(resource=NARROW)],
        [allow(not_resource=NARROW)],
    ),
    "allow NotResource, boundary Resource": (
        [allow(not_resource=NARROW)],
        [allow(resource=WIDE)],
    ),
    "allow NotResource, boundary on its exclusion": (
        [allow(not_resource=NARROW)],
        [allow(resource=NARROW)],
    ),
    "allow NotResource, boundary NotResource": (
        [allow(not_resource=NARROW)],
        [allow(not_resource=OTHER)],
    ),
    "partial overlap": (
        [allow(resource="arn:aws:s3:::*-prod/*")],
        [allow(resource="arn:aws:s3:::team-*/*")],
    ),
    "conditional boundary": (
        [allow(condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}})],
        [allow(condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})],
    ),
    "P29 boundary on another region": (
        [
            allow(condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}}),
            deny(
                condition={
                    "StringNotEquals": {
                        "aws:RequestedRegion": ["us-east-1", "eu-west-1"]
                    }
                }
            ),
        ],
        [allow(condition={"StringEquals": {"aws:RequestedRegion": "eu-west-1"}})],
    ),
    "two boundary statements": (
        [allow(resource=WIDE)],
        [allow(resource=NARROW), allow(resource=OTHER)],
    ),
    "boundary with a deny": (
        [allow(resource=WIDE)],
        [allow(), deny(resource=NARROW)],
    ),
    "boundary with a conditional deny": (
        [allow(resource=WIDE)],
        [allow(), deny(condition={"Bool": {"aws:ViaAWSService": "false"}})],
    ),
}


@pytest.mark.parametrize("statements, boundary", CASES.values(), ids=CASES.keys())
def test_matches_direct_evaluation(
    statements: List[Dict[str, Any]], boundary: List[Dict[str, Any]]
) -> None:
    assert mismatches(statements, boundary) == []


def test_action_the_boundary_doesnt_allow_is_ineffective() -> None:
    container = evaluate_role([allow()], boundary=[statement(action="s3:PutObject")])
    assert GET not in container.allowed_permissions
    assert {
        a.denied_by for a in container.ineffective_permissions if a.action == GET
    } == {f"Permission Boundary: {BOUNDARY}/0"}


def test_unrestricted_boundary_keeps_the_allow() -> None:
    container = evaluate_role([allow(resource=NARROW)], boundary=[allow()])
    assert {a.resource for a in container.allowed_permissions[GET]} == {NARROW}


def test_missing_boundary_policy_is_ignored() -> None:
    # the boundary ARN isn't in the account's policies: the identity is still evaluated
    auth = {"RoleDetailList": [role([allow(resource=NARROW)], boundary=BOUNDARY)]}
    assert {a.resource for a in evaluate(auth, ROLE).allowed_permissions[GET]} == {
        NARROW
    }
