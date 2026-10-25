from typing import Any, Dict, List, Optional, cast

from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.helper_classes import PermissionsContainer, PolicyWithSource
from iam_ape.helper_functions import normalize_policy
from iam_ape.helper_types import AwsPolicyType, EntityType

ACCOUNT = "111111111111"
ALICE = f"arn:aws:iam::{ACCOUNT}:user/alice"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/data"
BOUNDARY = f"arn:aws:iam::{ACCOUNT}:policy/boundary"


def statement(
    effect: str = "Allow",
    action: Any = "s3:GetObject",
    resource: Any = None,
    not_resource: Any = None,
    condition: Any = None,
    not_action: Any = None,
) -> Dict[str, Any]:
    built: Dict[str, Any] = {"Effect": effect}
    if not_action is not None:
        built["NotAction"] = not_action
    else:
        built["Action"] = action
    if resource is not None:
        built["Resource"] = resource
    if not_resource is not None:
        built["NotResource"] = not_resource
    if resource is None and not_resource is None:
        built["Resource"] = "*"
    if condition is not None:
        built["Condition"] = condition
    return built


def _document(statements: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": statements}


def user(
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
            {"PolicyName": "inline", "PolicyDocument": _document(statements)}
        ],
    }


def role(
    statements: List[Dict[str, Any]],
    tags: Optional[Dict[str, str]] = None,
    session_tags: bool = False,
    boundary: Optional[str] = None,
) -> Dict[str, Any]:
    built: Dict[str, Any] = {
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
            {"PolicyName": "inline", "PolicyDocument": _document(statements)}
        ],
    }
    if boundary:
        built["PermissionsBoundary"] = {
            "PermissionsBoundaryArn": boundary,
            "PermissionsBoundaryType": "Policy",
        }
    return built


def managed(arn: str, statements: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "Arn": arn,
        "PolicyName": arn.rsplit("/", 1)[-1],
        "DefaultVersionId": "v1",
        "PolicyVersionList": [
            {
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "Document": _document(statements),
            }
        ],
    }


def evaluate(
    auth: Dict[str, Any],
    arn: str,
    scp_levels: Optional[List[List[Dict[str, Any]]]] = None,
) -> PermissionsContainer:
    evaluator = EffectivePolicyEvaluator(
        AuthorizationDetails(
            {
                "RoleDetailList": [],
                "UserDetailList": [],
                "GroupDetailList": [],
                "Policies": [],
                **auth,
            }
        ),
        scp_levels=[
            [
                PolicyWithSource(
                    f"scp-{i}", normalize_policy(cast(AwsPolicyType, _document(level)))
                )
            ]
            for i, level in enumerate(scp_levels or [])
        ],
    )
    entity_type = EntityType.user if ":user/" in arn else EntityType.role
    return evaluator.evaluate(arn, entity_type)


def evaluate_role(
    statements: List[Dict[str, Any]],
    boundary: Optional[List[Dict[str, Any]]] = None,
    tags: Optional[Dict[str, str]] = None,
) -> PermissionsContainer:
    auth: Dict[str, Any] = {
        "RoleDetailList": [
            role(statements, tags=tags, boundary=BOUNDARY if boundary else None)
        ]
    }
    if boundary:
        auth["Policies"] = [managed(BOUNDARY, boundary)]
    return evaluate(auth, ROLE)
