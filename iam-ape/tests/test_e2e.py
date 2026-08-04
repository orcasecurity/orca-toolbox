import copy
import json
import os

from iam_ape.evaluator import (
    _PASSTHROUGH,
    AuthorizationDetails,
    EffectivePolicyEvaluator,
    _cached_deny_verdict,
)
from iam_ape.helper_classes import (
    Action,
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


def _action_view(action):
    return (
        action.action,
        action.resource,
        action.not_resource,
        _canonical(action.condition) if action.condition else None,
        action.source,
    )


def _perm_view(res):
    """Order-independent view of a result that keeps `source` — so a deny-cache re-stamp
    error (returning the wrong principal's source) shows up as a mismatch."""
    allowed = sorted(
        (_action_view(a) for s in res.allowed_permissions.values() for a in s),
        key=repr,
    )
    ineffective = sorted(
        ((_action_view(a), a.denied_by) for a in res.ineffective_permissions),
        key=repr,
    )
    return allowed, ineffective


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


def test_deny_cache_source_strip_matches_uncached() -> None:
    """The SCP deny cache keys on (action, resource, not_resource, condition) without source
    and re-stamps the caller's source on retrieval. Principals attaching *different* managed
    policies (distinct sources) that grant the *same* actions collide on that key, so this
    proves the shared, source-stripped cache reproduces exactly what a fresh per-principal
    evaluator computes — including the source stamped on every allowed/ineffective action."""
    grant_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "ec2:DescribeInstances"],
                "Resource": ["*"],
            }
        ],
    }
    mp_arns = [f"arn:aws:iam::123456789012:policy/mp{i}" for i in range(3)]
    names = ["R0", "R1", "R2"]
    auth_data = {
        "RoleDetailList": [
            _role_with_managed(n, arn) for n, arn in zip(names, mp_arns)
        ],
        "UserDetailList": [],
        "GroupDetailList": [],
        # Distinct ARNs, byte-identical content -> same stripped key, different source.
        "Policies": [_managed_policy(arn, grant_doc) for arn in mp_arns],
    }
    # Conditional Deny on s3:* -> s3 actions are *partially* denied (condition merged, exercising
    # the re-stamp path); ec2 is untouched (exercising the pass-through sentinel).
    deny_scp = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["s3:*"],
                "Resource": ["*"],
                "Condition": {"StringEquals": {"aws:RequestedRegion": ["us-east-1"]}},
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

    arns = [f"arn:aws:iam::123456789012:role/{n}" for n in names]
    auth = AuthorizationDetails(auth_data)

    standalone = {
        arn: _perm_view(
            EffectivePolicyEvaluator(auth, scps()).evaluate(
                arn=arn, entity_type=EntityType.role
            )
        )
        for arn in arns
    }
    shared_evaluator = EffectivePolicyEvaluator(auth, scps())
    shared = {
        arn: _perm_view(shared_evaluator.evaluate(arn=arn, entity_type=EntityType.role))
        for arn in arns
    }

    for arn in arns:
        assert shared[arn] == standalone[arn], f"{arn} deny-cache result diverged"

    # Both cache branches must actually have been exercised, else the test proves nothing.
    cache = shared_evaluator._scp_deny_result_cache
    assert any(v is _PASSTHROUGH for v in cache.values()), "sentinel path not exercised"
    assert any(
        v is not _PASSTHROUGH for v in cache.values()
    ), "re-stamp path not exercised"


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


def test_deny_cache_guard_skips_when_source_is_a_denied_source() -> None:
    """The source-stripped key is sound only where should_deny's exact-equality shortcut cannot
    fire — i.e. the action's source is not one of that action's denied sources. When it IS, the
    guard must refuse to cache; otherwise a later principal could hit an entry whose verdict was
    source-specific. This is the entire soundness argument for the stripped key, so pin it."""
    denied = {"s3:GetObject": {Action("s3:GetObject", "*", None, None, "p-deny")}}
    denied_sources = {"s3:GetObject": frozenset({"p-deny"})}

    # source is NOT a denied source -> safe to cache
    safe = Action(
        "s3:GetObject", "*", None, None, "arn:aws:iam::123456789012:policy/mp"
    )
    cache: dict = {}
    _cached_deny_verdict(safe, denied, cache, denied_sources)
    assert len(cache) == 1, "a non-colliding source must be cached"

    # source IS a denied source -> the equality shortcut can fire; guard must NOT cache
    colliding = Action("s3:GetObject", "*", None, None, "p-deny")
    guarded: dict = {}
    _cached_deny_verdict(colliding, denied, guarded, denied_sources)
    assert guarded == {}, "guard must not cache when the source is a denied source"


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
    assert set(stats) == {"expansion", "scp_deny", "merge"}
    for cache_stat in stats.values():
        assert isinstance(cache_stat["entries"], int)
        assert isinstance(cache_stat["weight"], int)
        assert cache_stat["capped"] is False
