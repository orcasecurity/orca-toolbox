import json
from typing import Any, Dict, Optional, Set, Tuple

from iam_ape.helper_types import EntityType
from iam_ape.policy_variables import resolve
from iam_ape.principal_scp import Principal
from tests.fixtures import ACCOUNT, ALICE, BOUNDARY, ROLE, evaluate, managed
from tests.fixtures import role as _role
from tests.fixtures import statement
from tests.fixtures import user as _user

GET = "s3:GetObject"


def _statement(
    resource: Any = None, not_resource: Any = None, condition: Any = None
) -> Dict[str, Any]:
    built = statement(resource=resource, not_resource=not_resource, condition=condition)
    built["Action"] = [GET]
    return built


def _scopes(
    auth: Dict[str, Any], arn: str
) -> Set[Tuple[Optional[str], Optional[str], Any]]:
    allowed = evaluate(auth, arn).allowed_permissions
    return {
        (
            a.resource,
            ",".join(a.not_resources) or None,
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
    boundary = managed(
        BOUNDARY, [_statement(resource="arn:aws:s3:::${aws:PrincipalTag/team}/*")]
    )
    role = _role([_statement(resource="*")], tags={"team": "data"}, boundary=BOUNDARY)
    assert _scopes({"RoleDetailList": [role], "Policies": [boundary]}, ROLE) == {
        ("arn:aws:s3:::data/*", None, None)
    }


def test_literal_escapes() -> None:
    principal = Principal.of(ALICE, {"UserName": "alice"}, EntityType.user)
    assert principal is not None
    assert resolve("arn:aws:s3:::${*}-${?}-${$}", principal) == "arn:aws:s3:::*-?-$"
