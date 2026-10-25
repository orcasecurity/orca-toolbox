import json
import logging
from collections import defaultdict
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from iam_ape.access import apply_denies, intersect, is_unrestricted, prune
from iam_ape.access import reset_caches as reset_access_caches
from iam_ape.conditions import reset_caches as reset_condition_caches
from iam_ape.exceptions import EntityNotFoundException, PolicyNotFoundException
from iam_ape.expand_policy import PolicyExpander
from iam_ape.helper_classes import (
    Action,
    IneffectiveAction,
    PermissionsContainer,
    PolicyWithSource,
)
from iam_ape.helper_functions import (
    deep_update,
    get_default_policy_for_managed_policy,
    merge_condition_cache_info,
    normalize_policy,
    reset_merge_condition_cache,
    sort_condition_values,
)
from iam_ape.helper_types import EntityType, FinalReportT
from iam_ape.policy_variables import for_principal, has_variables
from iam_ape.principal_scp import Principal, ScpLevel, is_service_linked_role

logger = logging.getLogger("IAM-APE:evaluator")


def _ineffective(action: Action, denied_by: str) -> IneffectiveAction:
    return IneffectiveAction(
        action=action.action,
        resource=action.resource,
        not_resources=action.not_resources,
        condition=action.condition,
        source=action.source,
        denied_by=denied_by,
    )


def _ordered(actions: Iterable[Action]) -> List[Action]:
    return sorted(actions, key=repr)


def explicitly_deny(
    permissions: PermissionsContainer,
) -> Tuple[Dict[str, Set[Action]], Set[IneffectiveAction]]:
    """Each allow after every deny of its action, applied one after another."""
    final_actions_dict: Dict[str, Set[Action]] = defaultdict(set)
    ineffective_permissions: Set[IneffectiveAction] = set()
    denied_permissions = permissions.denied_permissions
    for action_key, action_values in permissions.allowed_permissions.items():
        for action_value in action_values:
            denies = denied_permissions.get(action_value.action)
            if not denies:
                final_actions_dict[action_key].add(action_value)
                continue
            remaining, denied_by = apply_denies(action_value, _ordered(denies))
            if remaining:
                final_actions_dict[action_key].update(remaining)
            elif denied_by:
                ineffective_permissions.add(_ineffective(action_value, denied_by))
    return final_actions_dict, ineffective_permissions


def apply_permission_boundary(
    allow_actions: Dict[str, Set[Action]],
    permission_boundary: PermissionsContainer,
) -> Tuple[Dict[str, Set[Action]], Set[IneffectiveAction]]:
    """What a boundary (or one SCP level) lets through: the part of each allow one of its allow statements
    also allows, minus its denies."""

    def get_pb_id() -> str:
        for permissions in (
            permission_boundary.allowed_permissions,
            permission_boundary.denied_permissions,
        ):
            for values in permissions.values():
                if values:
                    return min(value.source for value in values)
        raise PolicyNotFoundException("Permission Boundary source not found")

    outside = f"Permission Boundary: {get_pb_id()}"
    new_allow_actions: Dict[str, Set[Action]] = defaultdict(set)
    ineffective_permissions: Set[IneffectiveAction] = set()
    for action_key, action_values in allow_actions.items():
        bounds = permission_boundary.allowed_permissions.get(action_key)
        for action_value in action_values:
            if not bounds:
                ineffective_permissions.add(_ineffective(action_value, outside))
                continue
            if any(is_unrestricted(bound) for bound in bounds):
                new_allow_actions[action_key].add(action_value)
                continue
            kept = {
                kept_action
                for bound in bounds
                for kept_action in intersect(action_value, bound)
            }
            if kept:
                new_allow_actions[action_key].update(prune(kept))
            else:
                ineffective_permissions.add(_ineffective(action_value, outside))

    allowed, denied_ineffective = explicitly_deny(
        PermissionsContainer(
            allowed_permissions=new_allow_actions,
            denied_permissions=permission_boundary.denied_permissions,
        )
    )
    ineffective_permissions.update(denied_ineffective)
    return allowed, ineffective_permissions


class AuthorizationDetails(object):
    def __init__(self, auth_report: Optional[Dict[str, Any]] = None):
        if auth_report is None:
            logger.error("Could not load account authorization details")
            auth_report = {}

        self.User: Dict[str, Any] = {
            user["Arn"]: user for user in auth_report.get("UserDetailList", [])
        }
        self.Group: Dict[str, Any] = {
            group["Arn"]: group for group in auth_report.get("GroupDetailList", [])
        }
        self.Role: Dict[str, Any] = {
            role["Arn"]: role for role in auth_report.get("RoleDetailList", [])
        }
        self.Policy: Dict[str, Any] = {
            policy["Arn"]: policy for policy in auth_report.get("Policies", [])
        }


class EffectivePolicyEvaluator:
    def __init__(
        self,
        authorization_details: AuthorizationDetails,
        scp_policies: Optional[List[PolicyWithSource]] = None,
        policy_expander: Optional[PolicyExpander] = None,
        scp_levels: Optional[List[List[PolicyWithSource]]] = None,
        org_id: Optional[str] = None,
        org_path: Optional[str] = None,
        is_management_account: bool = False,
    ) -> None:
        self.auth_details = authorization_details
        self.policy_expander = policy_expander or PolicyExpander()
        # The merge-condition memo is a module-global lru_cache; clear it here so its retention is
        # per-account (released at the account boundary), not accumulated process-wide.
        reset_merge_condition_cache()
        reset_access_caches()
        reset_condition_caches()
        # scp_policies is a single level (the SCPs attached to the account); scp_levels is every level of
        # the organization, root first. A principal must be allowed by each level.
        if scp_levels is None:
            scp_levels = [scp_policies] if scp_policies else []
        self.scp_levels = [
            ScpLevel(level, self.policy_expander) for level in scp_levels if level
        ]
        self.org_id = org_id
        self.org_path = org_path
        self.is_management_account = is_management_account
        self._boundaries: Dict[str, PermissionsContainer] = {}
        self._has_variables: Dict[str, bool] = {}

    def cache_stats(self) -> Dict[str, Dict[str, Any]]:
        """Per-cache footprint for memory diagnostics — log alongside RSS at a given principal
        count to see live cache size and whether a cap has been reached. Covers the expansion
        cache and the (per-account-cleared) merge-condition memo."""
        stats: Dict[str, Dict[str, Any]] = {}
        exp = self.policy_expander._expansion_cache
        stats["expansion"] = {
            "entries": len(exp),
            "weight": getattr(exp, "_weight", None),
            "capped": getattr(exp, "_capped", None),
        }
        info = merge_condition_cache_info()
        stats["merge"] = {
            "entries": info.currsize,
            "hits": info.hits,
            "misses": info.misses,
            # maxsize is None for an unbounded lru_cache; an unbounded memo is never capped.
            "capped": info.maxsize is not None and info.currsize >= info.maxsize,
        }
        return stats

    def create_json_report(
        self,
        permissions_container: PermissionsContainer,
        include_denied_permissions: bool = True,
    ) -> FinalReportT:
        def action_to_service(action: str) -> str:
            return action.split(":")[0]

        def _finalize(obj: Any) -> None:
            # In-place finalize, replacing a json.loads(json.dumps(...)) round-trip. The upload
            # path's json handler str()s sets (writing a Python repr, not a JSON array), so the
            # source / denied_by / NotResource sets MUST become lists here; sets stay sets during
            # the build above for dedup and are converted only now. Done in place (not by
            # building a copy) so the peak holds one structure, not the original + a ~330 MB
            # string + a parallel copy. defaultdict factories are cleared so the report reads
            # like the plain dict the round-trip produced (no auto-vivification on a missing key);
            # HashableDict/HashableList conditions are left as-is (they serialize as dict/list).
            if isinstance(obj, dict):
                if isinstance(obj, defaultdict):
                    obj.default_factory = None
                items = sorted(obj.items(), key=lambda item: str(item[0]))
                obj.clear()
                for key, value in items:
                    if isinstance(value, set):
                        value = sorted(value, key=str)
                    else:
                        _finalize(value)
                    obj[key] = value
            elif isinstance(obj, list):
                for i, value in enumerate(obj):
                    if isinstance(value, set):
                        obj[i] = sorted(value, key=str)
                    else:
                        _finalize(value)

        """
        {
            "allowed_permissions": {
                "<service>": {
                    "<resource>": {
                        "<access_level>": {
                            "action1": {"Condition: <condition>, "source": {<policy_arn>},
                            "action2": {"Condition: <condition>, "source": {<policy_arn>},
                        }
                    }
                }
            },
            "denied_permissions": {
                "<service>": {
                    "<resource>": {
                        "<access_level>": {
                            "action1": {"Condition: <condition>, "source": {<policy_arn>},
                            "action2": {"Condition: <condition>, "source": {<policy_arn>},
                        }
                    }
                }
            },
            "ineffective_permissions": {
                "<service>": {
                    "<resource>": {
                        "<access_level>": {
                            "action1": {
                                "denied_by": {<denied_by>}
                            },
                            "action2": {
                                "denied_by": {<denied_by>}
                            },
                        }
                    }
                }
            }
        }
        """
        res: FinalReportT = {
            "allowed_permissions": defaultdict(
                lambda: defaultdict(
                    lambda: defaultdict(
                        lambda: defaultdict(
                            lambda: {"Condition": None, "source": set()}
                        )
                    )
                )
            ),
            "denied_permissions": defaultdict(
                lambda: defaultdict(
                    lambda: defaultdict(
                        lambda: defaultdict(
                            lambda: {"Condition": None, "source": set()}
                        )
                    )
                )
            ),
            "ineffective_permissions": defaultdict(
                lambda: defaultdict(
                    lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
                )
            ),
        }
        # denied_permissions echoes the account-constant SCP deny expansion for every principal
        # (evaluate() unions it in, then never reads it back), so it carries no per-principal
        # information: an SCP's actual effect lands in allowed_permissions (conditions narrowed by
        # the negated deny) and ineffective_permissions (dropped actions, with denied_by). It is
        # also the section that scales with the SCP set, so building it dominates report time on
        # SCP-heavy accounts. Callers that don't read it can skip it.
        sections = (
            ("allowed_permissions", "denied_permissions")
            if include_denied_permissions
            else ("allowed_permissions",)
        )
        # An action allowed on a resource under several alternative conditions is allowed when any of them
        # holds: unconditionally if one is empty, else under the one condition or the list of them.
        alternatives: Dict[Tuple[str, str, str, str, str], Set[Any]] = defaultdict(set)
        for section in sections:
            for action_tuple_set in getattr(permissions_container, section).values():
                for action_tuple in action_tuple_set:
                    service = action_to_service(action_tuple.action)
                    resource = action_tuple.resource or "*"
                    curr_context = res[section][service][resource]  # type: ignore[literal-required]
                    if action_tuple.not_resources:
                        curr_context.setdefault("NotResource", set()).update(
                            action_tuple.not_resources
                        )
                    for access_level in self.policy_expander.get_action_access_levels(
                        action_tuple.action
                    ):
                        curr_context[access_level][action_tuple.action]["source"].add(
                            action_tuple.source
                        )
                        alternatives[
                            (
                                section,
                                service,
                                resource,
                                access_level,
                                action_tuple.action,
                            )
                        ].add(action_tuple.condition or None)
        for (
            section,
            service,
            resource,
            level,
            action,
        ), conditions in alternatives.items():
            entry = res[section][service][resource][level][action]  # type: ignore[literal-required]
            if None in conditions:
                entry["Condition"] = None
            elif len(conditions) == 1:
                entry["Condition"] = sort_condition_values(dict(next(iter(conditions))))
            else:
                entry["Condition"] = sorted(
                    (sort_condition_values(dict(c)) for c in conditions),
                    key=lambda c: json.dumps(c, sort_keys=True, default=str),
                )

        for action_tuple in permissions_container.ineffective_permissions:
            service = action_to_service(action_tuple.action)
            resource = action_tuple.resource or "*"
            if action_tuple.not_resources:
                res["ineffective_permissions"][service][resource].setdefault(
                    "NotResource", set()
                ).update(action_tuple.not_resources)
            for access_level in self.policy_expander.get_action_access_levels(
                action_tuple.action
            ):
                res["ineffective_permissions"][service][resource][access_level][
                    action_tuple.action
                ]["denied_by"].add(action_tuple.denied_by)

        _finalize(res)

        return res

    def get_direct_policies(
        self, entity_obj: Dict[str, Any], entity_type: EntityType
    ) -> List[PolicyWithSource]:
        inline_policies = [
            PolicyWithSource(
                policy.get("PolicyName", "inline policy"),
                normalize_policy(policy["PolicyDocument"]),
            )
            for policy in entity_obj.get(f"{entity_type.value}PolicyList", [])
        ]
        managed_policies = list(
            self.get_managed_policies(entity_obj.get("AttachedManagedPolicies", []))
        )
        return managed_policies + inline_policies

    def get_group_object_by_name(self, group_name: str) -> Optional[Dict[str, Any]]:
        for group in self.auth_details.Group.values():
            if group["GroupName"] == group_name:
                return group
        logger.warning(f"No such group {group_name}")
        return None

    def get_managed_policies(
        self, managed_policies: List[Dict[str, str]]
    ) -> Iterator[PolicyWithSource]:
        for policy_details in managed_policies:
            policy_arn = policy_details["PolicyArn"]
            if policy_obj := self.auth_details.Policy.get(policy_arn):
                policy = get_default_policy_for_managed_policy(policy_obj)
                yield PolicyWithSource(policy=policy, source=policy_arn)
            else:
                PolicyNotFoundException(f"Couldn't find policy {policy_arn}")

    def get_permission_boundary(
        self, entity: Dict[str, Any], principal: Optional[Principal] = None
    ) -> PermissionsContainer:
        pb_arn = entity.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
        if not pb_arn:
            return PermissionsContainer()
        if pb_arn in self._boundaries:
            return self._boundaries[pb_arn]
        policy = PolicyWithSource(
            source=pb_arn,
            policy=get_default_policy_for_managed_policy(
                self.auth_details.Policy.get(pb_arn, {})
            ),
        )
        if principal is not None and self._policy_has_variables(policy):
            return self.policy_expander.expand_policies(
                [for_principal(policy, principal)]
            )
        self._boundaries[pb_arn] = self.policy_expander.expand_policies([policy])
        return self._boundaries[pb_arn]

    def _policy_has_variables(self, policy: PolicyWithSource) -> bool:
        if not policy.source.startswith("arn:"):  # inline: its own document
            return has_variables(policy.policy)
        if policy.source not in self._has_variables:
            self._has_variables[policy.source] = has_variables(policy.policy)
        return self._has_variables[policy.source]

    def evaluate(self, arn: str, entity_type: EntityType) -> PermissionsContainer:
        entity_obj = getattr(self.auth_details, entity_type.value).get(arn)
        if not entity_obj:
            logger.error(f"Error - couldn't find entity with ARN {arn}")
            raise EntityNotFoundException(arn)

        direct_policies = self.get_direct_policies(entity_obj, entity_type)
        indirect_policies: List[PolicyWithSource] = []
        if entity_type == EntityType.user:
            for group in entity_obj.get("GroupList", []):
                group_obj = self.get_group_object_by_name(group)
                if group_obj:
                    indirect_policies.extend(
                        self.get_direct_policies(group_obj, EntityType.group)
                    )

        principal = Principal.of(
            arn, entity_obj, entity_type, self.org_id, self.org_path
        )
        direct_permissions = self.policy_expander.expand_policies(
            [
                for_principal(policy, principal)
                if self._policy_has_variables(policy)
                else policy
                for policy in direct_policies + indirect_policies
            ]
        )
        permission_boundary = self.get_permission_boundary(entity_obj, principal)

        final_permissions, ineffective_permissions = explicitly_deny(direct_permissions)

        denied_permissions = direct_permissions.denied_permissions
        scp_containers: List[PermissionsContainer] = []
        # SCPs don't apply to service-linked roles or to principals in the management account
        if not self.is_management_account and not is_service_linked_role(
            entity_obj, entity_type
        ):
            scp_containers = [
                level.for_principal(principal) for level in self.scp_levels
            ]
        for boundary in (permission_boundary, *scp_containers):
            if boundary.allowed_permissions or boundary.denied_permissions:
                (
                    final_permissions,
                    more_ineffective_permissions,
                ) = apply_permission_boundary(final_permissions, boundary)
                ineffective_permissions.update(more_ineffective_permissions)

                denied_permissions = deep_update(
                    denied_permissions,
                    boundary.denied_permissions,
                )

        return PermissionsContainer(
            allowed_permissions=final_permissions,
            denied_permissions=denied_permissions,
            ineffective_permissions=ineffective_permissions,
        )
