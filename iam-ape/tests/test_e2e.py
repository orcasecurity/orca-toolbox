import copy
import json
import os

from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.helper_classes import HashableDict, HashableList, PolicyWithSource
from iam_ape.helper_types import AwsPolicyType, EntityType

admin_policy: AwsPolicyType = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["*"],
            "Resource": ["*"],
        }
    ],
}

expected_result = {
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["ec2:*"],
            "Resource": ["*"],
            "Condition": {
                "StringEquals": {"aws:RequestedRegion": ["us-east-1"]},
                "Bool": {
                    "aws:MultiFactorAuthPresent": ["true"],
                    "aws:ViaAWSService": ["true"],
                },
            },
        },
        {
            "Effect": "Allow",
            "Action": [
                "organizations:DescribeAccount",
                "organizations:DescribeOrganization",
                "organizations:DescribeOrganizationalUnit",
                "organizations:DescribePolicy",
                "organizations:ListChildren",
                "organizations:ListParents",
                "organizations:ListPolicies",
                "organizations:ListPoliciesForTarget",
                "organizations:ListRoots",
                "organizations:ListTargetsForPolicy",
                "es:*",
            ],
            "Resource": ["*"],
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": ["true"],
                    "aws:ViaAWSService": ["true"],
                }
            },
        },
        {
            "Effect": "Allow",
            "Action": ["s3:Get*", "s3:List*", "s3:CreateBucket", "s3:CreateJob"],
            "Resource": [
                "arn:aws:s3:::cf-templates-hrlp5hbiotb8-us-east-1",
                "arn:aws:s3:::cf-templates-hrlp5hbiotb8-us-east-1/*",
            ],
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": ["true"],
                    "aws:ViaAWSService": ["true"],
                }
            },
        },
    ]
}


def test_e2e() -> None:
    with open(
        os.path.join(
            os.path.dirname(__file__),
            "test_data/test_account_authorizations_details.json",
        )
    ) as f:
        data = json.load(f)
    auth_details = AuthorizationDetails(data)

    assert len(auth_details.User) == 1
    assert len(auth_details.Group) == 3
    assert len(auth_details.Role) == 2
    assert len(auth_details.Policy) == 6

    with open(
        os.path.join(
            os.path.dirname(__file__),
            "test_data/test_scp_policy_1.json",
        )
    ) as f:
        data = json.load(f)
    scp_policies = [
        PolicyWithSource(
            data["Policy"]["PolicySummary"]["Arn"],
            json.loads(data["Policy"]["Content"]),
        )
    ]

    evaluator = EffectivePolicyEvaluator(auth_details, scp_policies)
    res = evaluator.evaluate(
        arn="arn:aws:iam::123456789012:user/TestUser1", entity_type=EntityType.user
    )

    assert len(res.allowed_permissions) > 600
    assert len(res.denied_permissions) > 13000
    assert len(res.ineffective_permissions) > 150

    minimized_policy = evaluator.policy_expander.shrink_policy(res.allowed_permissions)
    assert len(minimized_policy["Statement"]) == 3
    assert hash(HashableDict.recursively(minimized_policy)) == hash(  # type: ignore
        HashableDict.recursively(expected_result)
    )

    json_report = evaluator.create_json_report(res)

    def _distinct_action_count(section: dict) -> int:
        total = 0
        for service_map in section.values():
            for resource_map in service_map.values():
                actions: set = set()
                for level, level_map in resource_map.items():
                    if level == "NotResource":
                        continue
                    actions.update(level_map)
                total += len(actions)
        return total

    assert _distinct_action_count(json_report["allowed_permissions"]) == sum(
        [len(x) for x in res.allowed_permissions.values()]
    )
    assert _distinct_action_count(json_report["denied_permissions"]) == sum(
        [len(x) for x in res.denied_permissions.values()]
    )
    assert _distinct_action_count(json_report["ineffective_permissions"]) == len(
        res.ineffective_permissions
    )


def _canonical(obj):
    """Order-independent view of a report section for comparison; source sets
    serialize to lists whose order is not significant."""
    if isinstance(obj, dict):
        return {k: _canonical(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return sorted((_canonical(v) for v in obj), key=repr)
    return obj


def test_include_denied_permissions_preserves_read_sections() -> None:
    """create_json_report(include_denied_permissions=False) must drop only the
    never-read denied_permissions section and leave the consumer-read sections
    (allowed_permissions / ineffective_permissions) byte-identical."""
    with open(
        os.path.join(
            os.path.dirname(__file__),
            "test_data/test_account_authorizations_details.json",
        )
    ) as f:
        auth_details = AuthorizationDetails(json.load(f))
    with open(
        os.path.join(os.path.dirname(__file__), "test_data/test_scp_policy_1.json")
    ) as f:
        scp_data = json.load(f)
    scp_policies = [
        PolicyWithSource(
            scp_data["Policy"]["PolicySummary"]["Arn"],
            json.loads(scp_data["Policy"]["Content"]),
        )
    ]
    evaluator = EffectivePolicyEvaluator(auth_details, scp_policies)
    res = evaluator.evaluate(
        arn="arn:aws:iam::123456789012:user/TestUser1", entity_type=EntityType.user
    )

    full = evaluator.create_json_report(res)
    without_denied = evaluator.create_json_report(res, include_denied_permissions=False)

    assert full["denied_permissions"]  # fixture has a denied section to skip
    assert without_denied["denied_permissions"] == {}
    assert _canonical(without_denied["allowed_permissions"]) == _canonical(
        full["allowed_permissions"]
    )
    assert _canonical(without_denied["ineffective_permissions"]) == _canonical(
        full["ineffective_permissions"]
    )


def test_expand_minimize() -> None:
    evaluator = EffectivePolicyEvaluator(AuthorizationDetails({}), None)
    expanded_policy = evaluator.policy_expander.expand_policies(
        [PolicyWithSource(source="test", policy=admin_policy)]
    )
    minimized_policy = evaluator.policy_expander.shrink_policy(
        expanded_policy.allowed_permissions
    )

    assert hash(HashableList(minimized_policy["Statement"])) == hash(
        HashableList(admin_policy["Statement"])
    )


def _role(name: str, with_boundary: bool) -> dict:
    role = {
        "Arn": f"arn:aws:iam::123456789012:role/{name}",
        "RoleName": name,
        "RoleId": f"AROA{name}",
        "Path": "/",
        "AttachedManagedPolicies": [],
        "InstanceProfileList": [],
        "RolePolicyList": [
            {
                "PolicyName": "inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "s3:GetObject",
                                "s3:PutObject",
                                "ec2:DescribeInstances",
                            ],
                            "Resource": ["*"],
                        }
                    ],
                },
            }
        ],
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
    }
    if with_boundary:
        role["PermissionsBoundary"] = {
            "PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/pb",
            "PermissionsBoundaryType": "Policy",
        }
    return role


def test_shared_evaluator_matches_standalone() -> None:
    """One EffectivePolicyEvaluator reused across principals (the clouder pattern) must
    yield, per principal, exactly what a fresh per-principal evaluator yields. Regression
    guard for cross-principal condition aliasing: conditions reused across principals via
    the caches must never be mutated in place (e.g. by shrink_policy's normalize_policy)."""
    boundary_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*", "ec2:*"],
                "Resource": ["*"],
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            }
        ],
    }
    auth_data = {
        "RoleDetailList": [_role("R0", True), _role("R1", False), _role("R2", True)],
        "UserDetailList": [],
        "GroupDetailList": [],
        "Policies": [
            {
                "PolicyName": "pb",
                "Arn": "arn:aws:iam::123456789012:policy/pb",
                "PolicyId": "PB",
                "Path": "/",
                "DefaultVersionId": "v1",
                "PolicyVersionList": [
                    {
                        "Document": boundary_doc,
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                    }
                ],
            }
        ],
    }
    # Deny-bearing SCP with a *scalar* (un-normalized) condition — the in-place mutation trigger.
    deny_scp = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["s3:*"],
                "Resource": ["*"],
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            }
        ],
    }
    full_access = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }

    def scps() -> list:
        return [
            PolicyWithSource("p-FullAWSAccess", copy.deepcopy(full_access)),
            PolicyWithSource("p-deny", copy.deepcopy(deny_scp)),
        ]

    arns = [f"arn:aws:iam::123456789012:role/{n}" for n in ("R0", "R1", "R2")]

    def shrink_of(evaluator: EffectivePolicyEvaluator, arn: str):
        res = evaluator.evaluate(arn=arn, entity_type=EntityType.role)
        return _canonical(
            evaluator.policy_expander.shrink_policy(res.allowed_permissions)
        )

    auth = AuthorizationDetails(auth_data)
    standalone = {
        arn: shrink_of(EffectivePolicyEvaluator(auth, scps()), arn) for arn in arns
    }
    shared_evaluator = EffectivePolicyEvaluator(auth, scps())
    shared = {arn: shrink_of(shared_evaluator, arn) for arn in arns}

    for arn in arns:
        assert (
            shared[arn] == standalone[arn]
        ), f"{arn} result depends on evaluation order"


def test_shrink_does_not_mutate_shared_scp() -> None:
    """shrink_policy must not mutate the evaluator's shared scp_policy in place. Regression:
    normalize_policy rewrote a scalar condition value into a list, corrupting the SCP for
    every principal evaluated afterwards through the same (reused) evaluator."""
    role = _role("R1", with_boundary=False)
    auth = AuthorizationDetails(
        {
            "RoleDetailList": [role],
            "UserDetailList": [],
            "GroupDetailList": [],
            "Policies": [],
        }
    )
    # scalar (un-normalized) condition value is the mutation trigger
    deny_scp = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["s3:GetObject"],
                "Resource": ["*"],
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            }
        ],
    }
    full_access = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    evaluator = EffectivePolicyEvaluator(
        auth,
        [
            PolicyWithSource("p-FullAWSAccess", copy.deepcopy(full_access)),
            PolicyWithSource("p-deny", copy.deepcopy(deny_scp)),
        ],
    )

    def scp_conditions():
        return _canonical(
            [
                dict(a.condition)
                for actions in evaluator.scp_policy.denied_permissions.values()
                for a in actions
                if a.condition
            ]
        )

    before = scp_conditions()
    res = evaluator.evaluate(
        arn="arn:aws:iam::123456789012:role/R1", entity_type=EntityType.role
    )
    evaluator.policy_expander.shrink_policy(res.allowed_permissions)
    assert (
        scp_conditions() == before
    ), "shrink_policy mutated the shared scp_policy in place"
