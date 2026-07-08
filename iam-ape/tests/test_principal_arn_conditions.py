from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.helper_classes import PolicyWithSource
from iam_ape.helper_types import AwsPolicyType, EntityType

_ADMIN: AwsPolicyType = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
_FULL_AWS_ACCESS: AwsPolicyType = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
_GUARDRAIL_ACTIONS = [
    "bedrock:CreateGuardrail",
    "bedrock:UpdateGuardrail",
    "bedrock:DeleteGuardrail",
]
_SSO_ADMIN_PATTERN = "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_AdministratorAccess*"


def _scp(condition=None) -> AwsPolicyType:
    statement = {"Effect": "Deny", "Action": _GUARDRAIL_ACTIONS, "Resource": ["*"]}
    if condition:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


def _evaluate(arn: str, scp: AwsPolicyType):
    auth = AuthorizationDetails(
        {
            "UserDetailList": [
                {
                    "UserName": "u",
                    "Arn": arn,
                    "UserId": "AIDAEXAMPLE",
                    "Path": "/",
                    "UserPolicyList": [
                        {"PolicyName": "inline-admin", "PolicyDocument": _ADMIN}
                    ],
                    "AttachedManagedPolicies": [],
                    "GroupList": [],
                }
            ],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }
    )
    scp_policies = [
        PolicyWithSource("p-FullAWSAccess", _FULL_AWS_ACCESS),
        PolicyWithSource("p-scp", scp),
    ]
    evaluator = EffectivePolicyEvaluator(auth, scp_policies)
    return evaluator.evaluate(arn=arn, entity_type=EntityType.user)


def test_unconditional_deny_removes_action() -> None:
    res = _evaluate("arn:aws:iam::111122223333:role/AppRole", _scp())
    assert "bedrock:CreateGuardrail" not in res.allowed_permissions


def test_conditional_deny_applies_to_non_exempt_principal() -> None:
    condition = {"ArnNotLike": {"aws:PrincipalARN": [_SSO_ADMIN_PATTERN]}}
    res = _evaluate("arn:aws:iam::111122223333:role/AppRole", _scp(condition))
    assert "bedrock:CreateGuardrail" not in res.allowed_permissions


def test_conditional_deny_skipped_for_exempt_principal() -> None:
    condition = {"ArnNotLike": {"aws:PrincipalARN": [_SSO_ADMIN_PATTERN]}}
    exempt = (
        "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/"
        "us-east-1/AWSReservedSSO_AdministratorAccess_abc/admin"
    )
    res = _evaluate(exempt, _scp(condition))
    assert "bedrock:CreateGuardrail" in res.allowed_permissions


def test_non_principal_condition_stays_symbolic() -> None:
    condition = {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]}}
    res = _evaluate("arn:aws:iam::111122223333:role/AppRole", _scp(condition))
    assert "bedrock:CreateGuardrail" in res.allowed_permissions
