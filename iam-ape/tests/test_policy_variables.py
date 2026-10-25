import json
from typing import Any, Dict, List, Optional, Set, Tuple

from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.helper_types import EntityType
from iam_ape.policy_variables import resolve
from iam_ape.principal_scp import Principal

ACCOUNT = "111111111111"
ALICE = f"arn:aws:iam::{ACCOUNT}:user/alice"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/data"
GET = "s3:GetObject"


def _statement(
    resource: Any = None, not_resource: Any = None, condition: Any = None
) -> Dict[str, Any]:
    statement: Dict[str, Any] = {"Effect": "Allow", "Action": [GET]}
    if resource is not None:
        statement["Resource"] = resource
    if not_resource is not None:
        statement["NotResource"] = not_resource
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _user(
    statements: List[Dict[str, Any]], groups: Optional[List[str]] = None
) -> Dict[str, Any]:
    return {
        "Arn": ALICE,
        "UserName": "alice",
        "UserId": "AIDAALICE",
        "Path": "/",
        "GroupList": groups or [],
        "AttachedManagedPolicies": [],
        "Tags": [],
        "UserPolicyList": [
            {
                "PolicyName": "inline",
                "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
            }
        ],
    }


def _role(
    statements: List[Dict[str, Any]],
    tags: Optional[Dict[str, str]] = None,
    session_tags: bool = False,
    boundary: Optional[str] = None,
) -> Dict[str, Any]:
    role: Dict[str, Any] = {
        "Arn": ROLE,
        "RoleName": "data",
        "RoleId": "AROADATA",
        "Path": "/",
        "AttachedManagedPolicies": [],
        "InstanceProfileList": [],
        "Tags": [{"Key": k, "Value": v} for k, v in (tags or {}).items()],
        "AssumeRolePolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole"]
                    + (["sts:TagSession"] if session_tags else []),
                }
            ]
        },
        "RolePolicyList": [
            {
                "PolicyName": "inline",
                "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
            }
        ],
    }
    if boundary:
        role["PermissionsBoundary"] = {
            "PermissionsBoundaryArn": boundary,
            "PermissionsBoundaryType": "Policy",
        }
    return role


def _managed(arn: str, statements: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "Arn": arn,
        "PolicyName": arn.rsplit("/", 1)[-1],
        "DefaultVersionId": "v1",
        "PolicyVersionList": [
            {
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "Document": {"Version": "2012-10-17", "Statement": statements},
            }
        ],
    }


def _scopes(
    auth: Dict[str, Any], arn: str
) -> Set[Tuple[Optional[str], Optional[str], Any]]:
    evaluator = EffectivePolicyEvaluator(
        AuthorizationDetails(
            {
                "RoleDetailList": [],
                "UserDetailList": [],
                "GroupDetailList": [],
                "Policies": [],
                **auth,
            }
        )
    )
    entity_type = EntityType.user if ":user/" in arn else EntityType.role
    allowed = evaluator.evaluate(arn, entity_type).allowed_permissions
    return {
        (
            a.resource,
            a.not_resource,
            json.dumps(a.condition, sort_keys=True) if a.condition else None,
        )
        for a in allowed.get(GET, set())
    }


def test_username_in_resource() -> None:
    user = _user([_statement(resource="arn:aws:s3:::home/${aws:username}/*")])
    assert _scopes({"UserDetailList": [user]}, ALICE) == {
        ("arn:aws:s3:::home/alice/*", None, None)
    }


def test_variable_absent_for_the_principal_matches_nothing() -> None:
    # a role has no aws:username: the resource matches nothing, the other one still applies
    role = _role(
        [
            _statement(
                resource=[
                    "arn:aws:s3:::home/${aws:username}/*",
                    "arn:aws:s3:::shared/*",
                ]
            )
        ]
    )
    assert _scopes({"RoleDetailList": [role]}, ROLE) == {
        ("arn:aws:s3:::shared/*", None, None)
    }


def test_statement_whose_only_resource_matches_nothing_grants_nothing() -> None:
    role = _role([_statement(resource="arn:aws:s3:::home/${aws:username}/*")])
    assert _scopes({"RoleDetailList": [role]}, ROLE) == set()


def test_principal_tag_and_default() -> None:
    role = _role(
        [
            _statement(
                resource=[
                    "arn:aws:s3:::${aws:PrincipalTag/team}/*",
                    "arn:aws:s3:::${aws:PrincipalTag/project, 'common'}/*",
                ]
            )
        ],
        tags={"team": "data"},
    )
    assert _scopes({"RoleDetailList": [role]}, ROLE) == {
        ("arn:aws:s3:::data/*", None, None),
        ("arn:aws:s3:::common/*", None, None),
    }


def test_session_tags_leave_the_variable_as_written() -> None:
    role = _role(
        [_statement(resource="arn:aws:s3:::${aws:PrincipalTag/team}/*")],
        tags={"team": "data"},
        session_tags=True,
    )
    assert _scopes({"RoleDetailList": [role]}, ROLE) == {
        ("arn:aws:s3:::${aws:PrincipalTag/team}/*", None, None)
    }


def test_request_variable_is_left_as_written() -> None:
    role = _role([_statement(resource="arn:aws:s3:::logs/${aws:SourceIdentity}/*")])
    assert _scopes({"RoleDetailList": [role]}, ROLE) == {
        ("arn:aws:s3:::logs/${aws:SourceIdentity}/*", None, None)
    }


def test_not_resource_that_matches_nothing_excludes_nothing() -> None:
    role = _role([_statement(not_resource="arn:aws:s3:::home/${aws:username}/*")])
    assert _scopes({"RoleDetailList": [role]}, ROLE) == {("*", None, None)}


def test_condition_value() -> None:
    user = _user(
        [
            _statement(
                resource="*",
                condition={"StringLike": {"s3:prefix": ["${aws:username}/*"]}},
            )
        ]
    )
    assert _scopes({"UserDetailList": [user]}, ALICE) == {
        (
            "*",
            None,
            json.dumps({"StringLike": {"s3:prefix": ["alice/*"]}}, sort_keys=True),
        )
    }


def test_group_policy_reads_as_the_member() -> None:
    group = {
        "Arn": f"arn:aws:iam::{ACCOUNT}:group/devs",
        "GroupName": "devs",
        "Path": "/",
        "AttachedManagedPolicies": [],
        "GroupPolicyList": [
            {
                "PolicyName": "inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        _statement(resource="arn:aws:s3:::home/${aws:username}/*")
                    ],
                },
            }
        ],
    }
    user = _user([], groups=["devs"])
    assert _scopes({"UserDetailList": [user], "GroupDetailList": [group]}, ALICE) == {
        ("arn:aws:s3:::home/alice/*", None, None)
    }


def test_boundary_with_variables_is_resolved_per_principal() -> None:
    boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/boundary"
    boundary = _managed(
        boundary_arn, [_statement(resource="arn:aws:s3:::${aws:PrincipalTag/team}/*")]
    )
    role = _role(
        [_statement(resource="*")], tags={"team": "data"}, boundary=boundary_arn
    )
    assert _scopes({"RoleDetailList": [role], "Policies": [boundary]}, ROLE) == {
        ("arn:aws:s3:::data/*", None, None)
    }


def test_literal_escapes() -> None:
    principal = Principal.of(ALICE, {"UserName": "alice"}, EntityType.user)
    assert principal is not None
    assert resolve("arn:aws:s3:::${*}-${?}-${$}", principal) == "arn:aws:s3:::*-?-$"
