from typing import Any, Dict, List, cast

import pytest

from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.exceptions import InvalidArnException
from iam_ape.helper_classes import PermissionsContainer, PolicyWithSource
from iam_ape.helper_functions import normalize_policy
from iam_ape.helper_types import AwsPolicyType
from tests.fixtures import ACCOUNT, statement

ROOT = f"arn:aws:iam::{ACCOUNT}:root"
GET, DELETE = "s3:GetObject", "s3:DeleteObject"


def _root(
    scp: List[Dict[str, Any]], is_management_account: bool = False
) -> PermissionsContainer:
    # a FullAWSAccess-style allow plus the statements under test
    document = {"Version": "2012-10-17", "Statement": [statement(action="*"), *scp]}
    evaluator = EffectivePolicyEvaluator(
        AuthorizationDetails(
            {
                "RoleDetailList": [],
                "UserDetailList": [],
                "GroupDetailList": [],
                "Policies": [],
            }
        ),
        scp_levels=[
            [PolicyWithSource("scp-0", normalize_policy(cast(AwsPolicyType, document)))]
        ],
        is_management_account=is_management_account,
    )
    return evaluator.evaluate_root(ROOT)


def test_root_has_everything_the_scps_allow() -> None:
    container = _root([statement("Deny", DELETE)])
    assert GET in container.allowed_permissions
    assert DELETE not in container.allowed_permissions
    assert {
        a.denied_by for a in container.ineffective_permissions if a.action == DELETE
    }


def test_scps_dont_apply_to_the_management_account_root() -> None:
    container = _root([statement("Deny", DELETE)], is_management_account=True)
    assert DELETE in container.allowed_permissions


def test_deny_root_scp_by_principal_arn() -> None:
    # the usual "deny the root user" SCP
    container = _root(
        [
            statement(
                "Deny",
                "*",
                condition={"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}},
            )
        ]
    )
    assert not container.allowed_permissions


def test_root_principal_type_is_account() -> None:
    container = _root(
        [
            statement(
                "Deny",
                GET,
                condition={"StringEquals": {"aws:PrincipalType": "Account"}},
            )
        ]
    )
    assert GET not in container.allowed_permissions
    assert DELETE in container.allowed_permissions


def test_root_has_no_user_name() -> None:
    # aws:username is absent for root, so a positive match on it never applies
    container = _root(
        [statement("Deny", GET, condition={"StringLike": {"aws:username": "*"}})]
    )
    assert {a.condition for a in container.allowed_permissions[GET]} == {None}


def test_not_a_root_arn() -> None:
    with pytest.raises(InvalidArnException):
        EffectivePolicyEvaluator(AuthorizationDetails({})).evaluate_root(
            f"arn:aws:iam::{ACCOUNT}:user/alice"
        )
