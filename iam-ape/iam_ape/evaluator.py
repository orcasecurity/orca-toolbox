import json
import logging
from collections import defaultdict
from dataclasses import replace
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from iam_ape.consts import PolicyElement
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
    merge_condition,
    normalize_policy,
    wildcard_match,
)
from iam_ape.helper_types import EntityType, FinalReportT

logger = logging.getLogger("IAM-APE:evaluator")


def should_deny(
    iam_action: Action, denied_actions: Dict[str, Set[Action]]
) -> Tuple[bool, Set[Action], Optional[str]]:
    """
    Check if an action is denied by a list of denied actions
    :param iam_action:
    :param denied_actions:
    :return: denied, partially_denied_actions, source
    """
    res = set()
    partially_denied = False

    for denied_action in denied_actions.get(iam_action.action, []):

        if iam_action == denied_action:
            return True, set(), denied_action.source

        if iam_action.resource:

            if denied_action.resource:
                if iam_action.resource == denied_action.resource:
                    if not denied_action.condition:
                        return True, set(), denied_action.source
                    partially_denied = True
                    res.add(
                        Action(
                            action=iam_action.action,
                            resource=iam_action.resource,
                            not_resource=None,
                            condition=merge_condition(
                                iam_action.condition, denied_action.condition
                            ),
                            source=iam_action.source,
                        )
                    )
                elif wildcard_match(
                    iam_action.resource, denied_action.resource
                ):  # denied Resource > allowed Resource
                    if not denied_action.condition:
                        return True, set(), denied_action.source
                    partially_denied = True
                    res.add(
                        Action(
                            action=iam_action.action,
                            resource=iam_action.resource,
                            not_resource=None,
                            condition=merge_condition(
                                iam_action.condition, denied_action.condition
                            ),
                            source=iam_action.source,
                        )
                    )
                elif wildcard_match(
                    denied_action.resource, iam_action.resource
                ):  # allowed Resource > denied Resource
                    partially_denied = True
                    res.add(
                        Action(
                            action=iam_action.action,
                            resource=None
                            if iam_action.resource == PolicyElement.WILDCARD
                            else iam_action.resource,
                            not_resource=denied_action.resource,
                            condition=merge_condition(
                                iam_action.condition, denied_action.condition
                            ),
                            source=iam_action.source,
                        )
                    )
                else:  # scopes don't overlap
                    partially_denied = True
                    res.add(
                        Action(
                            action=iam_action.action,
                            resource=None
                            if iam_action.resource == PolicyElement.WILDCARD
                            else iam_action.resource,
                            not_resource=denied_action.resource,
                            condition=merge_condition(
                                iam_action.condition, denied_action.condition
                            ),
                            source=iam_action.source,
                        )
                    )

            if denied_action.not_resource:
                if denied_action.not_resource == iam_action.resource:
                    pass
                elif wildcard_match(
                    iam_action.resource, denied_action.not_resource
                ):  # denied NotResource > allowed Resource
                    pass
                elif wildcard_match(
                    denied_action.not_resource, iam_action.resource
                ):  # denied NotResource < allowed Resource
                    partially_denied = True
                    res.add(
                        Action(
                            action=iam_action.action,
                            resource=denied_action.not_resource,
                            not_resource=iam_action.not_resource,
                            condition=merge_condition(
                                iam_action.condition, denied_action.condition
                            ),
                            source=iam_action.source,
                        )
                    )

        if iam_action.not_resource:

            if denied_action.resource:
                if denied_action.resource == iam_action.not_resource:
                    pass
                elif wildcard_match(
                    denied_action.resource, iam_action.not_resource
                ):  # allowed NotResource > denied Resource
                    pass
                elif wildcard_match(
                    iam_action.not_resource, denied_action.resource
                ):  # denied Resource > allowed NotResource
                    partially_denied = True
                    res.add(
                        Action(
                            action=iam_action.action,
                            resource=iam_action.resource,
                            not_resource=denied_action.resource,
                            condition=merge_condition(
                                iam_action.condition, denied_action.condition
                            ),
                            source=iam_action.source,
                        )
                    )
                else:  # scopes don't overlap
                    partially_denied = True
                    res.add(
                        Action(
                            action=iam_action.action,
                            resource=iam_action.resource,
                            not_resource=denied_action.resource,
                            condition=merge_condition(
                                iam_action.condition, denied_action.condition
                            ),
                            source=iam_action.source,
                        )
                    )

            if denied_action.not_resource:
                if denied_action.not_resource == iam_action.not_resource:
                    if not denied_action.condition:
                        return True, set(), denied_action.source
                    partially_denied = True
                    res.add(
                        Action(
                            action=iam_action.action,
                            resource=None,
                            not_resource=iam_action.not_resource,
                            condition=merge_condition(
                                iam_action.condition, denied_action.condition
                            ),
                            source=iam_action.source,
                        )
                    )
                elif wildcard_match(
                    denied_action.not_resource, iam_action.not_resource
                ):  # allowed NotResource > denied NotResource
                    pass
                elif wildcard_match(
                    iam_action.not_resource, denied_action.not_resource
                ):  # denied NotResource > allowed NotResource
                    partially_denied = True
                    res.add(
                        Action(
                            action=iam_action.action,
                            resource=iam_action.resource,
                            not_resource=denied_action.not_resource,
                            condition=merge_condition(
                                iam_action.condition, denied_action.condition
                            ),
                            source=iam_action.source,
                        )
                    )
                else:  # scopes don't overlap
                    partially_denied = True
                    res.add(
                        Action(
                            action=iam_action.action,
                            resource=denied_action.not_resource,
                            not_resource=iam_action.not_resource,
                            condition=merge_condition(
                                iam_action.condition, denied_action.condition
                            ),
                            source=iam_action.source,
                        )
                    )

    if partially_denied:
        return False, res, None
    return False, {iam_action}, None


def explicitly_deny(
    permissions: PermissionsContainer,
) -> Tuple[Dict[str, Set[Action]], Set[IneffectiveAction]]:
    final_actions_dict: Dict[str, Set[Action]] = defaultdict(set)
    ineffective_permissions: Set[IneffectiveAction] = set()
    for action_key, action_values in permissions.allowed_permissions.items():
        for action_value in action_values:
            denied, new_action_values, denied_by = should_deny(
                action_value, permissions.denied_permissions
            )
            if not denied:
                final_actions_dict[action_key].update(new_action_values)
            elif denied_by:
                ineffective_permissions.add(
                    IneffectiveAction(
                        action=action_value.action,
                        resource=action_value.resource,
                        not_resource=action_value.not_resource,
                        condition=action_value.condition,
                        source=action_value.source,
                        denied_by=denied_by,
                    )
                )

    return final_actions_dict, ineffective_permissions


def apply_permission_boundary(
    allow_actions: Dict[str, Set[Action]],
    permission_boundary: PermissionsContainer,
) -> Tuple[Dict[str, Set[Action]], Set[IneffectiveAction]]:
    def permit(at: Action, bt: Action) -> Action:
        return replace(
            at,
            condition=merge_condition(at.condition, bt.condition, negate=False),
        )

    def deny(at: Action, boundary_id: str) -> IneffectiveAction:
        return IneffectiveAction(
            action=at.action,
            resource=at.resource,
            not_resource=at.not_resource,
            condition=at.condition,
            source=at.source,
            denied_by=f"Permission Boundary: {boundary_id}",
        )

    def get_pb_id() -> str:
        if permission_boundary.allowed_permissions:
            for values in permission_boundary.allowed_permissions.values():
                for value in values:
                    return value.source
        for values in permission_boundary.denied_permissions.values():
            for value in values:
                return value.source
        raise PolicyNotFoundException("Permission Boundary source not found")

    permission_boundary_id = get_pb_id()

    new_allow_actions = defaultdict(set)
    ineffective_permissions: Set[IneffectiveAction] = set()
    for action_key, action_values in allow_actions.items():
        if action_key not in permission_boundary.allowed_permissions.keys():
            # action is outside of boundary
            for action_value in action_values:
                ineffective_permissions.add(deny(action_value, permission_boundary_id))
        else:
            for action_tuple in action_values:
                if action_tuple in permission_boundary.allowed_permissions[action_key]:
                    new_allow_actions[action_key].add(
                        action_tuple
                    )  # action is permitted without change
                    continue
                for boundary_tuple in permission_boundary.allowed_permissions[
                    action_key
                ]:

                    if action_tuple.resource and boundary_tuple.resource:
                        if action_tuple.resource == boundary_tuple.resource:
                            new_allow_actions[action_key].add(
                                permit(action_tuple, boundary_tuple)
                            )  # action is permitted
                        elif wildcard_match(
                            action_tuple.resource, boundary_tuple.resource
                        ):
                            new_allow_actions[action_key].add(
                                permit(action_tuple, boundary_tuple)
                            )  # action is permitted
                        elif wildcard_match(
                            boundary_tuple.resource, action_tuple.resource
                        ):
                            new_allow_actions[action_key].add(
                                replace(
                                    action_tuple,
                                    resource=boundary_tuple.resource,
                                    condition=merge_condition(
                                        action_tuple.condition,
                                        boundary_tuple.condition,
                                        negate=False,
                                    ),
                                )
                            )
                        else:  # action is not permitted
                            ineffective_permissions.add(
                                deny(action_tuple, permission_boundary_id)
                            )

                    elif action_tuple.resource and boundary_tuple.not_resource:
                        if (
                            action_tuple.resource == boundary_tuple.not_resource
                        ):  # action is not permitted
                            ineffective_permissions.add(
                                deny(action_tuple, permission_boundary_id)
                            )
                        elif wildcard_match(
                            action_tuple.resource, boundary_tuple.not_resource
                        ):  # action is not permitted
                            ineffective_permissions.add(
                                deny(action_tuple, permission_boundary_id)
                            )
                        elif wildcard_match(
                            boundary_tuple.not_resource, action_tuple.resource
                        ):  # action is partially permitted
                            new_allow_actions[action_key].add(
                                replace(
                                    action_tuple,
                                    not_resource=boundary_tuple.not_resource,
                                    condition=merge_condition(
                                        action_tuple.condition,
                                        boundary_tuple.condition,
                                        negate=False,
                                    ),
                                )
                            )
                        else:  # action is permitted
                            new_allow_actions[action_key].add(
                                permit(action_tuple, boundary_tuple)
                            )

                    elif action_tuple.not_resource and boundary_tuple.resource:
                        if (
                            action_tuple.not_resource == boundary_tuple.resource
                        ):  # action is not permitted
                            ineffective_permissions.add(
                                deny(action_tuple, permission_boundary_id)
                            )
                        elif wildcard_match(
                            action_tuple.not_resource, boundary_tuple.resource
                        ):  # action is partially permitted
                            new_allow_actions[action_key].add(
                                replace(
                                    action_tuple,
                                    resource=boundary_tuple.resource,
                                    condition=merge_condition(
                                        action_tuple.condition,
                                        boundary_tuple.condition,
                                        negate=False,
                                    ),
                                )
                            )
                        elif wildcard_match(
                            boundary_tuple.resource, action_tuple.not_resource
                        ):  # action is not permitted
                            ineffective_permissions.add(
                                deny(action_tuple, permission_boundary_id)
                            )
                        else:  # action is partially permitted
                            new_allow_actions[action_key].add(
                                replace(
                                    action_tuple,
                                    resource=boundary_tuple.resource,
                                    not_resource=None,
                                    condition=merge_condition(
                                        action_tuple.condition,
                                        boundary_tuple.condition,
                                        negate=False,
                                    ),
                                )
                            )

                    elif action_tuple.not_resource and boundary_tuple.not_resource:
                        if (
                            action_tuple.not_resource == boundary_tuple.resource
                        ):  # action is permitted
                            new_allow_actions[action_key].add(
                                permit(action_tuple, boundary_tuple)
                            )
                        elif wildcard_match(
                            action_tuple.not_resource, boundary_tuple.not_resource
                        ):  # action is partially permitted
                            new_allow_actions[action_key].add(
                                replace(
                                    action_tuple,
                                    not_resource=boundary_tuple.not_resource,
                                )
                            )
                        elif wildcard_match(
                            boundary_tuple.not_resource, action_tuple.not_resource
                        ):  # action is permitted
                            new_allow_actions[action_key].add(
                                permit(action_tuple, boundary_tuple)
                            )
                        else:  # action is partially permitted
                            new_allow_actions[action_key].add(
                                replace(
                                    action_tuple,
                                    not_resource=boundary_tuple.not_resource,
                                    condition=merge_condition(
                                        action_tuple.condition,
                                        boundary_tuple.condition,
                                        negate=False,
                                    ),
                                )
                            )
                            new_allow_actions[action_key].add(
                                replace(
                                    action_tuple,
                                    not_resource=action_tuple.not_resource,
                                    condition=merge_condition(
                                        action_tuple.condition,
                                        boundary_tuple.condition,
                                        negate=False,
                                    ),
                                )
                            )

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
    ) -> None:
        self.auth_details = authorization_details
        self.policy_expander = policy_expander or PolicyExpander()
        self.scp_policy = (
            self.policy_expander.expand_policies(scp_policies)
            if scp_policies
            else PermissionsContainer()
        )

    def create_json_report(
        self, permissions_container: PermissionsContainer
    ) -> FinalReportT:
        def action_to_service(action: str) -> str:
            return action.split(":")[0]

        def serialize_set(obj):
            if isinstance(obj, set):
                return list(obj)
            return obj

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
        sections = ("allowed_permissions", "denied_permissions")
        for section in sections:
            for action_tuple_set in getattr(permissions_container, section).values():
                for action_tuple in action_tuple_set:
                    service = action_to_service(action_tuple.action)
                    resource = action_tuple.resource or "*"
                    if action_tuple.not_resource:
                        if res[section][service][resource].get("NotResource"):  # type: ignore[literal-required]
                            res[section][service][resource]["NotResource"].add(  # type: ignore[literal-required]
                                action_tuple.not_resource
                            )
                        else:
                            res[section][service][resource]["NotResource"] = {  # type: ignore[literal-required]
                                action_tuple.not_resource
                            }
                    access_level = self.policy_expander.get_action_access_level(
                        action_tuple.action
                    )
                    if cond := merge_condition(
                        res[section][service][resource][access_level]  # type: ignore[literal-required]
                        .get(action_tuple.action, {})
                        .get("Condition", {}),
                        action_tuple.condition,
                        negate=False,
                        hashable=False,
                    ):
                        res[section][service][resource][access_level][  # type: ignore[literal-required]
                            action_tuple.action
                        ][
                            "Condition"
                        ] = cond
                    res[section][service][resource][access_level][action_tuple.action][  # type: ignore
                        "source"
                    ].add(
                        action_tuple.source
                    )

        for action_tuple in permissions_container.ineffective_permissions:
            service = action_to_service(action_tuple.action)
            resource = action_tuple.resource or "*"
            if action_tuple.not_resource:
                if res["ineffective_permissions"][service][resource].get("NotResource"):
                    res["ineffective_permissions"][service][resource][
                        "NotResource"
                    ].add(action_tuple.not_resource)
                else:
                    res["ineffective_permissions"][service][resource]["NotResource"] = {
                        action_tuple.not_resource
                    }
            access_level = self.policy_expander.get_action_access_level(
                action_tuple.action
            )
            res["ineffective_permissions"][service][resource][access_level][
                action_tuple.action
            ]["denied_by"].add(action_tuple.denied_by)

        res = json.loads(json.dumps(res, default=serialize_set))

        return res

    def get_direct_policies(
        self, entity_obj: Dict[str, Any], entity_type: EntityType
    ) -> List[PolicyWithSource]:
        inline_policies = [
            PolicyWithSource(
                "inline policy", normalize_policy(policy["PolicyDocument"])
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

    def get_permission_boundary(self, entity: Dict[str, Any]) -> PermissionsContainer:
        permissions = PermissionsContainer()
        if pb_arn := entity.get("PermissionsBoundary", {}).get(
            "PermissionsBoundaryArn"
        ):
            policy = PolicyWithSource(
                source=pb_arn,
                policy=get_default_policy_for_managed_policy(
                    self.auth_details.Policy.get(pb_arn, {})
                ),
            )
            permissions = self.policy_expander.expand_policies([policy])
            permissions.allowed_permissions, _ = explicitly_deny(permissions)

        return permissions

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

        direct_permissions = self.policy_expander.expand_policies(
            direct_policies + indirect_policies
        )
        permission_boundary = self.get_permission_boundary(entity_obj)

        final_permissions, ineffective_permissions = explicitly_deny(direct_permissions)

        denied_permissions = direct_permissions.denied_permissions
        for boundary in (permission_boundary, self.scp_policy):
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
