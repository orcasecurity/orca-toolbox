import copy
import json
import os

from iam_ape.evaluator import AuthorizationDetails, EffectivePolicyEvaluator
from iam_ape.helper_classes import (
    CappedMemoCache,
    HashableDict,
    HashableList,
    PolicyWithSource,
)
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


def _find_surviving_set(obj, path="report"):
    """Return the path to the first ``set`` reachable in ``obj``, or None."""
    if isinstance(obj, set):
        return path
    if isinstance(obj, dict):
        for key, value in obj.items():
            if hit := _find_surviving_set(value, f"{path}.{key}"):
                return hit
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            if hit := _find_surviving_set(value, f"{path}[{index}]"):
                return hit
    return None


def test_create_json_report_emits_no_sets() -> None:
    """create_json_report's in-place _finalize must convert every set to a list. The S3 upload
    path serializes with a json handler that str()s an unexpected set (a Python repr, not a JSON
    array) instead of raising, so a surviving set corrupts the blob silently. Assert no set
    survives anywhere in the returned report, and that json.dumps accepts it with no default=."""
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
    report = evaluator.create_json_report(res)

    # the fixture populates allowed/denied/ineffective, so source + denied_by sets are all present
    assert report["allowed_permissions"]
    assert report["ineffective_permissions"]
    surviving = _find_surviving_set(report)
    assert surviving is None, f"set survived _finalize at {surviving}"
    json.dumps(
        report
    )  # no default= => a surviving set (or non-list HashableList) would raise


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

    def outputs_of(evaluator: EffectivePolicyEvaluator, arn: str):
        # Compare BOTH contracts per principal: shrink_policy (Contract B) and the full
        # create_json_report (Contract A). The report path carries the shared merged conditions
        # this PR is built around, so a cache-aliasing regression that shrink_policy misses shows
        # up here.
        res = evaluator.evaluate(arn=arn, entity_type=EntityType.role)
        shrunk = _canonical(
            evaluator.policy_expander.shrink_policy(res.allowed_permissions)
        )
        report = _canonical(evaluator.create_json_report(res))
        return shrunk, report

    auth = AuthorizationDetails(auth_data)
    standalone = {
        arn: outputs_of(EffectivePolicyEvaluator(auth, scps()), arn) for arn in arns
    }
    shared_evaluator = EffectivePolicyEvaluator(auth, scps())
    shared = {arn: outputs_of(shared_evaluator, arn) for arn in arns}

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


def _managed_policy(arn: str, doc: dict) -> dict:
    return {
        "PolicyName": arn.rsplit("/", 1)[-1],
        "Arn": arn,
        "PolicyId": arn.rsplit("/", 1)[-1].upper(),
        "Path": "/",
        "DefaultVersionId": "v1",
        "PolicyVersionList": [
            {"Document": doc, "VersionId": "v1", "IsDefaultVersion": True}
        ],
    }


def _role_with_managed(name: str, mp_arn: str) -> dict:
    return {
        "Arn": f"arn:aws:iam::123456789012:role/{name}",
        "RoleName": name,
        "RoleId": f"AROA{name}",
        "Path": "/",
        "AttachedManagedPolicies": [{"PolicyName": mp_arn, "PolicyArn": mp_arn}],
        "InstanceProfileList": [],
        "RolePolicyList": [],
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
    }


def test_capped_memo_cache_stops_inserting_at_cap() -> None:
    """CappedMemoCache skips a new key once it would exceed the cap (graceful degradation to
    uncached) while keeping the hot early entries — it must NOT thrash-clear. A smaller entry
    that still fits is accepted; clear() resets the counter."""
    cache: CappedMemoCache = CappedMemoCache(
        max_weight=5, weigh=lambda v: len(v), name="test"
    )
    cache["a"] = [1, 1]  # weight 2
    cache["b"] = [1, 1]  # weight 4
    assert set(cache) == {"a", "b"}
    assert cache._weight == 4
    cache["c"] = [1, 1]  # 4+2=6 > 5 -> skipped, early entries kept
    assert set(cache) == {"a", "b"}
    assert cache._weight == 4
    cache["d"] = [1]  # 4+1=5 <= 5 -> a smaller entry still fits
    assert "d" in cache
    assert cache._weight == 5
    cache["e"] = [1]  # 5+1=6 > 5 -> skipped
    assert "e" not in cache
    # Re-inserting an existing key must not double-count toward the weight.
    cache["a"] = [9, 9, 9]
    assert cache._weight == 5
    cache.clear()
    assert len(cache) == 0
    assert cache._weight == 0
    assert cache._capped is False


def test_cache_stats_reports_live_cache_weight() -> None:
    """cache_stats() exposes per-cache entries/weight/capped so a caller can log the live cache
    footprint next to RSS — the number that tells whether a cap is bounding what actually grows."""
    grant_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]}
        ],
    }
    mp_arn = "arn:aws:iam::123456789012:policy/mp"
    auth = AuthorizationDetails(
        {
            "RoleDetailList": [_role_with_managed("R0", mp_arn)],
            "UserDetailList": [],
            "GroupDetailList": [],
            "Policies": [_managed_policy(mp_arn, grant_doc)],
        }
    )
    scps = [
        PolicyWithSource(
            "p-FullAWSAccess",
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            },
        )
    ]
    evaluator = EffectivePolicyEvaluator(auth, scps)
    evaluator.evaluate(
        arn="arn:aws:iam::123456789012:role/R0", entity_type=EntityType.role
    )

    stats = evaluator.cache_stats()
    assert set(stats) == {"expansion", "merge"}
    for cache_stat in stats.values():
        assert isinstance(cache_stat["entries"], int)
        assert cache_stat["capped"] is False
    # the process-global merge memo must be reported (F1) and reset per evaluator
    assert isinstance(stats["merge"]["hits"], int)
    fresh = EffectivePolicyEvaluator(auth, scps)
    assert (
        fresh.cache_stats()["merge"]["entries"] == 0
    ), "merge memo not cleared per evaluator"
