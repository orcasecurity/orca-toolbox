from typing import Any, Dict, List, Optional, Set, cast

import pytest

from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.helper_classes import PolicyWithSource
from iam_ape.helper_functions import normalize_policy
from iam_ape.helper_types import AwsPolicyType, EntityType
from iam_ape.principal_scp import Principal, decide_clause, statement_for_principal

ACCOUNT = "111111111111"
DATA_ROLE = f"arn:aws:iam::{ACCOUNT}:role/data"
ADMIN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/admin-ops"
SERVICE_LINKED_ROLE = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-service-role/s3.amazonaws.com/AWSServiceRoleForS3"
)
USER = f"arn:aws:iam::{ACCOUNT}:user/alice"
ORG_ID = "o-abc123"
ORG_PATH = f"{ORG_ID}/r-root/ou-root-team/"


def _role(
    arn: str,
    tags: Optional[Dict[str, str]] = None,
    trust_actions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    name = arn.rsplit("/", 1)[-1]
    return {
        "Arn": arn,
        "RoleName": name,
        "RoleId": f"AROA{name.upper()}",
        "Path": arn.split(":role", 1)[1][: -len(name)],
        "AttachedManagedPolicies": [],
        "InstanceProfileList": [],
        "Tags": [{"Key": k, "Value": v} for k, v in (tags or {}).items()],
        "AssumeRolePolicyDocument": {
            "Statement": [
                {"Effect": "Allow", "Action": trust_actions or ["sts:AssumeRole"]}
            ]
        },
        "RolePolicyList": [
            {
                "PolicyName": "inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "ec2:DescribeInstances"],
                            "Resource": "*",
                        }
                    ],
                },
            }
        ],
    }


def _user(arn: str) -> Dict[str, Any]:
    name = arn.rsplit("/", 1)[-1]
    return {
        "Arn": arn,
        "UserName": name,
        "UserId": "AIDAALICE",
        "Path": "/",
        "GroupList": [],
        "AttachedManagedPolicies": [],
        "Tags": [],
        "UserPolicyList": [
            {
                "PolicyName": "inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}
                    ],
                },
            }
        ],
    }


def _scp(name: str, *statements: Dict[str, Any]) -> PolicyWithSource:
    return PolicyWithSource(
        f"arn:aws:organizations::{ACCOUNT}:policy/{name}",
        normalize_policy(
            cast(
                AwsPolicyType, {"Version": "2012-10-17", "Statement": list(statements)}
            )
        ),
    )


FULL_ACCESS = _scp(
    "p-FullAWSAccess", {"Effect": "Allow", "Action": "*", "Resource": "*"}
)


def _allowed(
    roles: List[Dict[str, Any]],
    arn: str,
    scp_levels: Optional[List[List[PolicyWithSource]]] = None,
    scp_policies: Optional[List[PolicyWithSource]] = None,
    users: Optional[List[Dict[str, Any]]] = None,
    **kwargs: Any,
) -> Dict[str, Set[Any]]:
    """action -> conditions it is allowed under (None = unconditionally)."""
    auth = AuthorizationDetails(
        {
            "RoleDetailList": roles,
            "UserDetailList": users or [],
            "GroupDetailList": [],
            "Policies": [],
        }
    )
    evaluator = EffectivePolicyEvaluator(
        auth, scp_policies=scp_policies, scp_levels=scp_levels, **kwargs
    )
    entity_type = EntityType.user if ":user/" in arn else EntityType.role
    result: Dict[str, Set[Any]] = {}
    for actions in evaluator.evaluate(arn, entity_type).allowed_permissions.values():
        for action in actions:
            condition = (
                tuple(
                    sorted(
                        (op, k)
                        for op, kv in (action.condition or {}).items()
                        for k in kv
                    )
                )
                or None
            )
            result.setdefault(action.action, set()).add(condition)
    return result


class TestLevels:
    def test_every_level_must_allow(self) -> None:
        ou_allows_ec2_only = _scp(
            "ou-ec2-only", {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}
        )
        allowed = _allowed(
            [_role(DATA_ROLE)],
            DATA_ROLE,
            scp_levels=[[FULL_ACCESS], [ou_allows_ec2_only], [FULL_ACCESS]],
        )
        assert "ec2:DescribeInstances" in allowed
        assert "s3:GetObject" not in allowed

    def test_merged_list_is_one_level(self) -> None:
        # The old input: every level in one list unions their allows, so the OU allow-list is lost.
        ou_allows_ec2_only = _scp(
            "ou-ec2-only", {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}
        )
        allowed = _allowed(
            [_role(DATA_ROLE)],
            DATA_ROLE,
            scp_policies=[FULL_ACCESS, ou_allows_ec2_only],
        )
        assert "s3:GetObject" in allowed

    def test_deny_at_any_level_denies(self) -> None:
        root_denies_s3 = _scp(
            "root-deny-s3", {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}
        )
        allowed = _allowed(
            [_role(DATA_ROLE)],
            DATA_ROLE,
            scp_levels=[[FULL_ACCESS, root_denies_s3], [FULL_ACCESS]],
        )
        assert "s3:GetObject" not in allowed
        assert "ec2:DescribeInstances" in allowed

    def test_single_level_matches_the_old_input(self) -> None:
        denies_s3 = _scp(
            "deny-s3", {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}
        )
        old = _allowed(
            [_role(DATA_ROLE)], DATA_ROLE, scp_policies=[FULL_ACCESS, denies_s3]
        )
        new = _allowed(
            [_role(DATA_ROLE)], DATA_ROLE, scp_levels=[[FULL_ACCESS, denies_s3]]
        )
        assert old == new

    def test_no_scps(self) -> None:
        assert _allowed([_role(DATA_ROLE)], DATA_ROLE, scp_levels=[]) == _allowed(
            [_role(DATA_ROLE)], DATA_ROLE
        )


class TestExemptions:
    ROOT_DENIES_S3 = _scp(
        "root-deny-s3", {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}
    )

    def test_service_linked_role_is_not_subject_to_scps(self) -> None:
        allowed = _allowed(
            [_role(SERVICE_LINKED_ROLE)],
            SERVICE_LINKED_ROLE,
            scp_levels=[[FULL_ACCESS, self.ROOT_DENIES_S3]],
        )
        assert "s3:GetObject" in allowed

    def test_role_named_like_a_service_linked_role_is_not_exempt(self) -> None:
        lookalike = f"arn:aws:iam::{ACCOUNT}:role/team/aws-service-role-copy"
        allowed = _allowed(
            [_role(lookalike)],
            lookalike,
            scp_levels=[[FULL_ACCESS, self.ROOT_DENIES_S3]],
        )
        assert "s3:GetObject" not in allowed

    def test_management_account_is_not_subject_to_scps(self) -> None:
        allowed = _allowed(
            [_role(DATA_ROLE)],
            DATA_ROLE,
            scp_levels=[[FULL_ACCESS, self.ROOT_DENIES_S3]],
            is_management_account=True,
        )
        assert "s3:GetObject" in allowed


class TestPrincipalConditions:
    DENY_S3_EXCEPT_ADMINS_OUTSIDE_US_EAST_1 = _scp(
        "deny-s3-unless-admin",
        {
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {
                "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/admin-*"},
                "StringNotEquals": {"aws:RequestedRegion": "us-east-1"},
            },
        },
    )

    def test_deny_that_names_the_principal_keeps_only_the_request_clause(self) -> None:
        allowed = _allowed(
            [_role(DATA_ROLE)],
            DATA_ROLE,
            scp_levels=[[FULL_ACCESS, self.DENY_S3_EXCEPT_ADMINS_OUTSIDE_US_EAST_1]],
        )
        assert allowed["s3:GetObject"] == {(("StringEquals", "aws:RequestedRegion"),)}

    def test_deny_that_exempts_the_principal_is_dropped(self) -> None:
        allowed = _allowed(
            [_role(ADMIN_ROLE)],
            ADMIN_ROLE,
            scp_levels=[[FULL_ACCESS, self.DENY_S3_EXCEPT_ADMINS_OUTSIDE_US_EAST_1]],
        )
        assert allowed["s3:GetObject"] == {None}

    def test_group_keeps_every_clause(self) -> None:
        statement = self.DENY_S3_EXCEPT_ADMINS_OUTSIDE_US_EAST_1.policy["Statement"][0]
        assert statement_for_principal(statement, None) == statement

    def test_same_outcome_shares_one_expansion(self) -> None:
        roles = [_role(DATA_ROLE), _role(f"arn:aws:iam::{ACCOUNT}:role/data-2")]
        auth = AuthorizationDetails(
            {
                "RoleDetailList": roles,
                "UserDetailList": [],
                "GroupDetailList": [],
                "Policies": [],
            }
        )
        evaluator = EffectivePolicyEvaluator(
            auth,
            scp_levels=[[FULL_ACCESS, self.DENY_S3_EXCEPT_ADMINS_OUTSIDE_US_EAST_1]],
        )
        level = evaluator.scp_levels[0]
        first = level.for_principal(
            Principal.of(roles[0]["Arn"], roles[0], EntityType.role)
        )
        second = level.for_principal(
            Principal.of(roles[1]["Arn"], roles[1], EntityType.role)
        )
        assert first is second


def _principal(arn: str = DATA_ROLE, **entity: Any) -> Principal:
    entity_type = EntityType.user if ":user/" in arn else EntityType.role
    principal = Principal.of(arn, entity, entity_type, ORG_ID, ORG_PATH)
    assert principal is not None
    return principal


@pytest.mark.parametrize(
    "operator, key, values, expected",
    [
        ("ArnLike", "aws:PrincipalArn", "arn:aws:iam::*:role/data", True),
        ("ArnNotLike", "aws:PrincipalArn", "arn:aws:iam::*:role/data", False),
        ("ArnLike", "aws:PrincipalArn", "arn:aws:iam::*:role/dat?", True),
        # ArnLike matches each colon-separated field on its own: `*` can't span the account field
        ("ArnLike", "aws:PrincipalArn", "arn:aws:iam:*::role/data", False),
        ("ArnLike", "aws:PrincipalArn", "*", True),
        ("StringLike", "aws:PrincipalArn", "arn:aws:iam::[0-9]*:role/data", False),
        ("StringEquals", "aws:PrincipalAccount", ACCOUNT, True),
        ("StringNotEquals", "aws:PrincipalAccount", ["222222222222", ACCOUNT], False),
        ("StringEquals", "aws:PrincipalOrgID", ORG_ID, True),
        (
            "ForAnyValue:StringLike",
            "aws:PrincipalOrgPaths",
            f"{ORG_ID}/r-root/ou-root-team/*",
            True,
        ),
        (
            "ForAnyValue:StringNotLike",
            "aws:PrincipalOrgPaths",
            f"{ORG_ID}/r-root/ou-root-team/*",
            False,
        ),
        (
            "ForAllValues:StringNotLike",
            "aws:PrincipalArn",
            "arn:aws:iam::*:role/admin-*",
            True,
        ),
        ("StringEquals", "aws:PrincipalType", "AssumedRole", True),
        ("Bool", "aws:PrincipalIsAWSService", "false", True),
        ("StringEqualsIgnoreCase", "aws:PrincipalType", "assumedrole", True),
        ("StringEquals", "aws:PrincipalTag/team", "data", True),
        ("StringNotEquals", "aws:PrincipalTag/team", "data", False),
        # a tag the principal doesn't have: positive operators fail, negated ones hold
        ("StringEquals", "aws:PrincipalTag/missing", "x", False),
        ("StringNotEquals", "aws:PrincipalTag/missing", "x", True),
        ("StringEqualsIfExists", "aws:PrincipalTag/missing", "x", True),
        ("Null", "aws:PrincipalTag/missing", "true", True),
        ("Null", "aws:PrincipalTag/team", "true", False),
        ("ForAnyValue:StringEquals", "aws:PrincipalTag/missing", "x", False),
        ("ForAllValues:StringEquals", "aws:PrincipalTag/missing", "x", True),
        # aws:username is absent for a role
        ("StringEquals", "aws:username", "data", False),
    ],
)
def test_decide_clause(operator: str, key: str, values: Any, expected: bool) -> None:
    principal = _principal(DATA_ROLE, Tags=[{"Key": "team", "Value": "data"}])
    assert decide_clause(operator, key, values, principal) is expected


@pytest.mark.parametrize(
    "operator, key, values",
    [
        (
            "StringLike",
            "aws:userid",
            "AROADATA:*",
        ),  # the session name comes from the caller
        ("NumericLessThan", "aws:PrincipalTag/level", "3"),  # operator not modelled
        (
            "ArnLike",
            "aws:PrincipalArn",
            "arn:aws:iam:*role/data",
        ),  # not a six-field ARN pattern
    ],
)
def test_clause_left_to_the_request(operator: str, key: str, values: Any) -> None:
    assert (
        decide_clause(
            operator, key, values, _principal(Tags=[{"Key": "level", "Value": "2"}])
        )
        is None
    )


def test_session_tags_leave_principal_tags_undecided() -> None:
    principal = _principal(
        DATA_ROLE,
        Tags=[{"Key": "team", "Value": "data"}],
        AssumeRolePolicyDocument={
            "Statement": [
                {"Effect": "Allow", "Action": ["sts:AssumeRole", "sts:TagSession"]}
            ]
        },
    )
    assert (
        decide_clause("StringEquals", "aws:PrincipalTag/team", "data", principal)
        is None
    )


def test_org_keys_undecided_without_org_data() -> None:
    principal = Principal.of(DATA_ROLE, {}, EntityType.role)
    assert principal is not None
    assert (
        decide_clause("StringEquals", "aws:PrincipalOrgID", ORG_ID, principal) is None
    )


def test_user_keys() -> None:
    principal = _principal(USER, UserName="alice", UserId="AIDAALICE")
    assert decide_clause("StringEquals", "aws:username", "alice", principal) is True
    assert decide_clause("StringEquals", "aws:userid", "AIDAALICE", principal) is True
    assert decide_clause("StringEquals", "aws:PrincipalType", "User", principal) is True


def test_scp_on_user_by_username() -> None:
    deny_alice = _scp(
        "deny-alice",
        {
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:username": "alice"}},
        },
    )
    allowed = _allowed(
        [], USER, users=[_user(USER)], scp_levels=[[FULL_ACCESS, deny_alice]]
    )
    assert "s3:GetObject" not in allowed
