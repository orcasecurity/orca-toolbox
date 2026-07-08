from typing import Any

from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.helper_classes import PolicyWithSource
from iam_ape.helper_types import EntityType

_GUARDRAIL_ACTIONS = [
    "bedrock:CreateGuardrail",
    "bedrock:UpdateGuardrail",
    "bedrock:DeleteGuardrail",
]
_SSO_ADMIN_PATTERN = "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_AdministratorAccess*"


def _policy(*statements: Any) -> Any:
    return {"Version": "2012-10-17", "Statement": list(statements)}


_ADMIN = _policy({"Effect": "Allow", "Action": ["*"], "Resource": ["*"]})
_FULL_AWS_ACCESS = _policy({"Effect": "Allow", "Action": ["*"], "Resource": ["*"]})


def _scp(condition: Any = None) -> Any:
    statement: Any = {"Effect": "Deny", "Action": _GUARDRAIL_ACTIONS, "Resource": ["*"]}
    if condition:
        statement["Condition"] = condition
    return _policy(statement)


def _evaluate(arn: str, scp: Any, tags: Any = None) -> Any:
    user = {
        "UserName": "u",
        "Arn": arn,
        "UserId": "AIDAEXAMPLE",
        "Path": "/",
        "UserPolicyList": [{"PolicyName": "inline-admin", "PolicyDocument": _ADMIN}],
        "AttachedManagedPolicies": [],
        "GroupList": [],
        "Tags": [{"Key": k, "Value": v} for k, v in (tags or {}).items()],
    }
    auth = AuthorizationDetails(
        {
            "UserDetailList": [user],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }
    )
    scps = [
        PolicyWithSource("p-FullAWSAccess", _FULL_AWS_ACCESS),
        PolicyWithSource("p-scp", scp),
    ]
    return EffectivePolicyEvaluator(auth, scps).evaluate(
        arn=arn, entity_type=EntityType.user
    )


def _allows_guardrail(res) -> bool:
    return "bedrock:CreateGuardrail" in res.allowed_permissions


def test_unconditional_deny_removes_action() -> None:
    assert not _allows_guardrail(
        _evaluate("arn:aws:iam::111122223333:user/App", _scp())
    )


def test_arn_condition_applies_to_non_exempt_principal() -> None:
    cond = {"ArnNotLike": {"aws:PrincipalARN": [_SSO_ADMIN_PATTERN]}}
    assert not _allows_guardrail(
        _evaluate("arn:aws:iam::111122223333:user/App", _scp(cond))
    )


def test_arn_condition_skipped_for_exempt_principal() -> None:
    cond = {"ArnNotLike": {"aws:PrincipalARN": [_SSO_ADMIN_PATTERN]}}
    exempt = (
        "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/"
        "us-east-1/AWSReservedSSO_AdministratorAccess_abc/admin"
    )
    assert _allows_guardrail(_evaluate(exempt, _scp(cond)))


def test_account_condition_applies_to_non_allowed_account() -> None:
    cond = {"StringNotEquals": {"aws:PrincipalAccount": ["999988887777"]}}
    assert not _allows_guardrail(
        _evaluate("arn:aws:iam::111122223333:user/App", _scp(cond))
    )


def test_account_condition_skipped_for_allowed_account() -> None:
    cond = {"StringNotEquals": {"aws:PrincipalAccount": ["111122223333"]}}
    assert _allows_guardrail(
        _evaluate("arn:aws:iam::111122223333:user/App", _scp(cond))
    )


def test_mixed_arn_and_account_condition_and_semantics() -> None:
    # Real p-gh487uoz shape: deny unless allowed account OR exempt SSO role.
    cond = {
        "StringNotEquals": {"aws:PrincipalAccount": ["999988887777"]},
        "ArnNotLike": {"aws:PrincipalARN": [_SSO_ADMIN_PATTERN]},
    }
    # non-allowed account AND non-exempt role -> deny applies -> removed
    assert not _allows_guardrail(
        _evaluate("arn:aws:iam::111122223333:user/App", _scp(cond))
    )
    # allowed account -> account clause false -> deny does NOT apply -> kept
    assert _allows_guardrail(
        _evaluate("arn:aws:iam::999988887777:user/App", _scp(cond))
    )


def test_principal_tag_condition_resolved() -> None:
    cond = {"StringNotEquals": {"aws:PrincipalTag/team": ["ai-platform"]}}
    denied = _evaluate("arn:aws:iam::111122223333:user/App", _scp(cond), {"team": "x"})
    kept = _evaluate(
        "arn:aws:iam::111122223333:user/App", _scp(cond), {"team": "ai-platform"}
    )
    assert not _allows_guardrail(denied)
    assert _allows_guardrail(kept)


def test_absent_tag_stays_symbolic() -> None:
    cond = {"StringNotEquals": {"aws:PrincipalTag/team": ["ai-platform"]}}
    # principal has no such tag -> undecidable -> kept symbolic (alert still fires)
    assert _allows_guardrail(
        _evaluate("arn:aws:iam::111122223333:user/App", _scp(cond))
    )


def test_non_principal_condition_stays_symbolic() -> None:
    cond = {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]}}
    assert _allows_guardrail(
        _evaluate("arn:aws:iam::111122223333:user/App", _scp(cond))
    )


def test_mixed_with_unresolvable_key_stays_symbolic() -> None:
    cond = {
        "ArnNotLike": {"aws:PrincipalARN": [_SSO_ADMIN_PATTERN]},
        "StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]},
    }
    assert _allows_guardrail(
        _evaluate("arn:aws:iam::111122223333:user/App", _scp(cond))
    )
