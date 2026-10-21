import functools
import json
import logging
import re
import tarfile
from collections import defaultdict
from fnmatch import fnmatch, fnmatchcase
from typing import Any, Dict, FrozenSet, List, Literal, Optional, Set, Tuple

from requests.structures import CaseInsensitiveDict

from iam_ape.consts import (
    AWS_PARTITION_RE,
    CROSS_SERVICE_RESOURCES,
    RESOURCE_ARN_RE,
    PolicyElement,
    actions_json_location,
)
from iam_ape.exceptions import UnknownServiceExepction
from iam_ape.helper_classes import (
    Action,
    HashableDict,
    HashableList,
    PermissionsContainer,
    PolicyWithSource,
)
from iam_ape.helper_functions import as_list, normalize_policy, wildcard_match
from iam_ape.helper_types import AwsPolicyStatementType, AwsPolicyType

logger = logging.getLogger("policy expander")
WORDSPLIT_RE = re.compile(r"(?<=.)(?=[A-Z])")


class FrozenSetSet:
    pass


@functools.lru_cache()
def shorten_to_leading_word(actions: FrozenSet[str]) -> Dict[str, Set[str]]:
    """
    Shorten a list of actions to their leading word,
    e.g. ['DescribeInstances', 'DescribeVolumes'] -> {'Describe': ['DescribeInstances', 'DescribeVolumes']}
    :param actions: list of actions
    :returns: dict of leading words to actions
    """
    action_mapping = defaultdict(set)
    for action in actions:
        action_words = WORDSPLIT_RE.split(action)
        action_mapping[action_words[0]].add(action)
    return action_mapping


# One entry per service: with the default 128 a full pass over the services evicts each before its next use
@functools.lru_cache(maxsize=None)
def exact_leading_word_wildcards(actions: FrozenSet[str]) -> Dict[str, Set[str]]:
    """
    The leading-word groups whose "Word*", read as AWS reads it (a case-insensitive prefix glob),
    matches exactly the group's actions. kms "Re" (ReEncryptFrom, ReEncryptTo) is not one of them,
    as "kms:Re*" also matches ReplicateKey, RetireGrant and RevokeGrant.
    :param actions: all actions of a service
    :returns: dict of leading words to actions
    """
    return {
        word: group
        for word, group in shorten_to_leading_word(actions).items()
        if sum(action.lower().startswith(word.lower()) for action in actions)
        == len(group)
    }


def minimize_actions(
    service: str, actions: List[str], all_iam_actions: List[str]
) -> List[str]:
    """
    Minimize a list of actions for a given service, by replacing a list of actions with a wildcard if possible.
    :param service: service name
    :param actions: list of actions
    :return: a list of actions
    """
    if len(actions) == len(all_iam_actions):
        return [f"{service}:*"]
    if len(actions) == 1:
        return [f"{service}:{actions[0]}"]
    all_service_wildcards = exact_leading_word_wildcards(frozenset(all_iam_actions))
    statements_wildcards = shorten_to_leading_word(frozenset(actions))
    res = []
    for wildcard, used_actions in statements_wildcards.items():
        if len(used_actions) == len(all_service_wildcards.get(wildcard, ())):
            res.append(f"{service}:{wildcard}*")
        else:
            res.extend([f"{service}:{action}" for action in used_actions])
    return sorted(res)


def _condition_sort_key(action: Action) -> str:
    return json.dumps(action.condition, sort_keys=True)


def _ordered_statement(statement: AwsPolicyStatementType) -> AwsPolicyStatementType:
    elements = (
        PolicyElement.EFFECT,
        PolicyElement.ACTION,
        PolicyElement.RESOURCE,
        PolicyElement.NOTRESOURCE,
        PolicyElement.CONDITION,
    )
    return {e: statement[e] for e in elements if e in statement}  # type: ignore[return-value,literal-required]


def _append_action(
    res: Dict[str, Set[Action]],
    action: str,
    service: str,
    resources: Optional[List[str]],
    not_resources: Optional[List[str]],
    condition: Optional[Dict[str, Any]],
    source: str,
    explicit_action: bool = False,
) -> None:
    def has_wildcard(value: str) -> bool:
        return "*" in value or "?" in value

    def relevant_resource(resource: str, action_service: str) -> bool:
        resource = resource.lower()
        if resource in (
            "*",
            "arn:*",
            "arn:aws:*",
            "arn:aws-cn:*",
            "arn:aws-us-gov:*",
        ):
            return True
        match = RESOURCE_ARN_RE.match(resource)
        if not match:
            return False
        partition, resource_service = match.group("partition", "service")
        if resource_service is None:
            return has_wildcard(partition)
        if not has_wildcard(partition) and not AWS_PARTITION_RE.fullmatch(partition):
            return False
        services = {action_service.lower()} | CROSS_SERVICE_RESOURCES.get(
            action_service.lower(), frozenset()
        )
        return any(fnmatchcase(s, resource_service) for s in services)

    def relevant(values: Optional[List[str]], keep_unmatched: bool) -> List[str]:
        matched = [v for v in values or [] if relevant_resource(v, service)]
        return matched if matched or not keep_unmatched else values or []

    # A statement naming this action but no resource it can target still meant those resources for it
    resources = relevant(resources, keep_unmatched=explicit_action)
    # A NotResource that can't match the action excludes nothing, so dropping the action would under-report
    not_resources = relevant(not_resources, keep_unmatched=True)

    for resource in resources:
        if condition:
            for key, val in condition.items():
                res[action].add(
                    Action(
                        action=action,
                        resource=resource,
                        not_resource=None,
                        condition=HashableDict.recursively({key: val}),
                        source=source,
                    )
                )
        else:
            res[action].add(
                Action(
                    action=action,
                    resource=resource,
                    not_resource=None,
                    condition=None,
                    source=source,
                )
            )
    for not_resource in not_resources:
        if condition:
            for key, val in condition.items():
                res[action].add(
                    Action(
                        action=action,
                        resource=None,
                        not_resource=not_resource,
                        condition=HashableDict.recursively({key: val}),
                        source=source,
                    )
                )
        else:
            res[action].add(
                Action(
                    action=action,
                    resource=None,
                    not_resource=not_resource,
                    condition=None,
                    source=source,
                )
            )


class PolicyExpander:
    def __init__(self, all_iam_actions_file_location: Optional[str] = None) -> None:
        self.all_iam_actions: CaseInsensitiveDict = self._init_iam_actions(
            all_iam_actions_file_location
        )
        self._all_service_wildcards: List[str] = [
            f"{k}:*" for k, v in self.all_iam_actions.items() if len(v) > 0
        ]

    @staticmethod
    def _init_iam_actions(
        all_iam_actions_file_location: Optional[str] = None,
    ) -> CaseInsensitiveDict:
        res: CaseInsensitiveDict = CaseInsensitiveDict()
        file_path = all_iam_actions_file_location or actions_json_location
        try:
            with tarfile.open(file_path) as f:
                data = json.load(f.extractfile("actions.json"))  # type: ignore
                for k, v in data.items():
                    res[k] = CaseInsensitiveDict(v)
        except Exception as e:
            logger.exception(f"Failed to load AWS IAM Actions due to {e}")
        return res

    def normalize_action(self, action: str) -> str:
        service, permission = action.split(":", maxsplit=1)
        permission = self.all_iam_actions[service]._store[permission.lower()][0]
        return f"{service}:{permission}"

    def expand_policies(self, policies: List[PolicyWithSource]) -> PermissionsContainer:
        allow_actions_dict: Dict[str, Set[Action]] = defaultdict(set)
        deny_actions_dict: Dict[str, Set[Action]] = defaultdict(set)

        all_actions: Dict[Literal["Allow", "Deny"], Dict[str, Set[Action]]] = {
            PolicyElement.ALLOW: allow_actions_dict,
            PolicyElement.DENY: deny_actions_dict,
        }

        for source, policy in policies:
            if policy is None:
                continue
            for i, statement in enumerate(policy["Statement"]):
                sid = "{}/{}".format(source, statement.get("Sid", i))
                if actions := statement.get(PolicyElement.ACTION):
                    for action in actions:
                        expanded_action = self.expand_action(
                            Action(
                                action=action,
                                resource=statement.get(PolicyElement.RESOURCE),
                                not_resource=statement.get(PolicyElement.NOTRESOURCE),
                                condition=statement.get(PolicyElement.CONDITION),
                                source=sid,
                            )
                        )
                        for action_key, action_values in expanded_action.items():
                            all_actions[statement[PolicyElement.EFFECT]][
                                action_key
                            ].update(action_values)

                elif statement.get(PolicyElement.NOTACTION):
                    expanded_notaction = self.expand_not_action(statement, sid)
                    for action_key, action_values in expanded_notaction.items():
                        all_actions[statement[PolicyElement.EFFECT]][action_key].update(
                            action_values
                        )

        return PermissionsContainer(
            allowed_permissions=all_actions[PolicyElement.ALLOW],
            denied_permissions=all_actions[PolicyElement.DENY],
        )

    def expand_action(self, iam_action: Action) -> Dict[str, Set[Action]]:
        res: Dict[str, Set[Action]] = defaultdict(set)
        try:
            if iam_action.action == PolicyElement.WILDCARD:  # {"Action": ["*"]}
                for service, action_dicts in self.all_iam_actions.items():
                    for action in action_dicts.keys():
                        _append_action(
                            res=res,
                            service=service,
                            action=f"{service}:{action}",
                            resources=as_list(iam_action.resource),
                            not_resources=as_list(iam_action.not_resource),
                            condition=iam_action.condition,
                            source=iam_action.source,
                        )
            elif PolicyElement.WILDCARD in iam_action.action:  # {"Action": ["iam:*"]}
                service, wildcard_action = iam_action.action.split(":", maxsplit=1)
                for action in self.all_iam_actions[service].keys():
                    if fnmatch(action.lower(), wildcard_action.lower()):
                        _append_action(
                            res=res,
                            service=service,
                            action=f"{service}:{action}",
                            resources=as_list(iam_action.resource),
                            not_resources=as_list(iam_action.not_resource),
                            condition=iam_action.condition,
                            source=iam_action.source,
                        )
            else:  # {"Action": ["sts:GetCallerIdentity"]}
                service, action = iam_action.action.split(":", maxsplit=1)
                _append_action(
                    res=res,
                    service=service,
                    action=self.normalize_action(iam_action.action),
                    resources=as_list(iam_action.resource),
                    not_resources=as_list(iam_action.not_resource),
                    condition=iam_action.condition,
                    source=iam_action.source,
                    explicit_action=True,
                )
        except KeyError:  # not a valid action
            logger.debug(f"Got an invalid action: {iam_action.action}")

        return res

    def expand_not_action(
        self, statement: AwsPolicyStatementType, sid: str
    ) -> Dict[str, Set[Action]]:
        res: Dict[str, Set[Action]] = defaultdict(set)
        notactions: List[str] = statement.get(PolicyElement.NOTACTION) or []
        if any(
            [notaction == PolicyElement.WILDCARD for notaction in notactions]
        ):  # {"NotAction": ["*"]}
            # This is here as a safeguard. No sane person should write a policy like this. It has no effect.
            pass
        else:  # {"NotAction": ["ec2:*", "iam:Get*", "sts:GetCallerIdentity"]}
            for iam_service, action_dicts in self.all_iam_actions.items():
                for action in action_dicts.keys():
                    curr_action = f"{iam_service}:{action}"
                    curr_action_lower = curr_action.lower()
                    if any(
                        [
                            wildcard_match(curr_action_lower, not_action.lower())
                            for not_action in notactions
                        ]
                    ):
                        continue
                    _append_action(
                        res=res,
                        action=curr_action,
                        service=iam_service,
                        resources=statement.get(PolicyElement.RESOURCE),
                        not_resources=statement.get(PolicyElement.NOTRESOURCE),
                        condition=statement.get(PolicyElement.CONDITION),
                        source=sid,
                    )

        return res

    def get_action_access_levels(self, action: str) -> List[str]:
        service, action_key = action.split(":", maxsplit=1)
        access = self.all_iam_actions[service][action_key]["access"]
        return [level.strip() for level in access.split(",")] if access else []

    def deflate_policy_statements(
        self,
        policy_statements: List[AwsPolicyStatementType],
    ) -> List[AwsPolicyStatementType]:
        for statement in policy_statements:
            action_dict = defaultdict(list)
            for action in statement.get(PolicyElement.ACTION) or []:
                service, action_key = action.split(":", maxsplit=1)
                action_dict[service].append(action_key)
            statement_actions = []
            for service, action_keys in action_dict.items():
                if all_service_actions := self.all_iam_actions.get(service):
                    statement_actions.extend(
                        minimize_actions(
                            service=service,
                            actions=action_keys,
                            all_iam_actions=all_service_actions,
                        )
                    )
                else:
                    raise UnknownServiceExepction(service)
            if all(
                [
                    action in as_list(statement_actions)
                    for action in self._all_service_wildcards
                ]
            ):
                statement_actions = ["*"]
            statement[PolicyElement.ACTION] = statement_actions
        return policy_statements

    def shrink_policy(self, allow_actions: Dict[str, Set[Action]]) -> AwsPolicyType:
        policy_res: AwsPolicyType = {"Statement": []}
        squashed_policies: Set[Action] = set()
        for allow_action_set in allow_actions.values():
            squashed_policies.update(allow_action_set)

        # Arrange by source, action, resource, and not_resource to detect split conditions
        actions_by_source_action_resource: Dict[
            Tuple[str, str, Optional[str], Optional[str]], List[Action]
        ] = defaultdict(list)

        for action_tuple in squashed_policies:
            source_key = (
                action_tuple.source,
                action_tuple.action,
                action_tuple.resource,
                action_tuple.not_resource,
            )
            actions_by_source_action_resource[source_key].append(action_tuple)

        # Merge conditions for actions from the same source
        merged_actions: Set[Action] = set()
        for actions_list in actions_by_source_action_resource.values():
            if len(actions_list) == 1:
                merged_actions.add(actions_list[0])
            else:
                # Multiple actions with same source/action/resource - merge their conditions
                merged_condition: Dict[str, Any] = {}
                for action in sorted(actions_list, key=_condition_sort_key):
                    if action.condition:
                        for operator, operator_conditions in action.condition.items():
                            if operator in merged_condition:
                                if isinstance(
                                    merged_condition[operator], dict
                                ) and isinstance(operator_conditions, dict):
                                    merged_condition[operator].update(
                                        operator_conditions
                                    )
                            else:
                                merged_condition[operator] = operator_conditions

                # Create a new merged action
                merged_action = Action(
                    action=actions_list[0].action,
                    resource=actions_list[0].resource,
                    not_resource=actions_list[0].not_resource,
                    condition=merged_condition if merged_condition else None,
                    source=actions_list[0].source,
                )
                merged_actions.add(merged_action)

        # Arrange by Resource/NotResource
        by_resource_notresource: Dict[
            Tuple[Optional[str], Optional[str]], Dict[Optional[HashableDict], Set[str]]
        ] = defaultdict(lambda: defaultdict(set))
        for action_tuple in merged_actions:
            by_resource_notresource[(action_tuple.resource, action_tuple.not_resource)][
                HashableDict.recursively(action_tuple.condition)
            ].add(action_tuple.action)

        # Arrange by Action/Condition/NotResource
        by_action_condition_notresource: Dict[
            Tuple[FrozenSet[str], Optional[HashableDict], Optional[str]], Set[str]
        ] = defaultdict(set)
        for resource_notresource, condition_actions in by_resource_notresource.items():
            resource, notresource = resource_notresource
            for condition, actions_set in condition_actions.items():
                key: Tuple[FrozenSet[str], Optional[HashableDict], Optional[str]] = (
                    frozenset(actions_set),
                    condition,
                    notresource,
                )
                if resource:
                    by_action_condition_notresource[key].add(resource)
                elif not by_action_condition_notresource.get(key):
                    by_action_condition_notresource[key] = set()

        statements = list()
        for (
            action_condition_notresource,
            resources,
        ) in by_action_condition_notresource.items():
            actions, condition, notresource = action_condition_notresource
            statement: AwsPolicyStatementType = {
                "Effect": "Allow",
                PolicyElement.ACTION: sorted(list(actions)),
            }
            if resources:
                statement[PolicyElement.RESOURCE] = sorted([r for r in resources])
            if notresource:
                statement[PolicyElement.NOTRESOURCE] = as_list(notresource)
            if condition:
                statement[PolicyElement.CONDITION] = condition
            statements.append(statement)

        deflated_statements = self.deflate_policy_statements(statements)

        final_statements: Dict[int, AwsPolicyStatementType] = {}
        for statement in deflated_statements:
            statement_key = hash(
                (
                    HashableList(statement[PolicyElement.ACTION] or []),
                    HashableDict.recursively(statement.get(PolicyElement.CONDITION)),
                )
            )
            if statement_key in final_statements.keys():
                rsrc = (
                    final_statements[statement_key].get(PolicyElement.RESOURCE) or []
                ) + (statement.get(PolicyElement.RESOURCE) or [])
                if rsrc:
                    final_statements[statement_key][PolicyElement.RESOURCE] = sorted(
                        set(rsrc)
                    )
                not_rsrc = (
                    final_statements[statement_key].get(PolicyElement.NOTRESOURCE) or []
                ) + (statement.get(PolicyElement.NOTRESOURCE) or [])
                if not_rsrc:
                    final_statements[statement_key][PolicyElement.NOTRESOURCE] = sorted(
                        set(not_rsrc)
                    )
            else:
                final_statements[statement_key] = statement

        admin_statement: AwsPolicyStatementType = {
            PolicyElement.EFFECT: PolicyElement.ALLOW,
            PolicyElement.ACTION: [PolicyElement.WILDCARD],
            PolicyElement.RESOURCE: [PolicyElement.WILDCARD],
        }
        if any(
            [statement == admin_statement for statement in final_statements.values()]
        ):
            policy_res["Statement"] = [admin_statement]
        else:
            policy_res["Statement"] = sorted(
                (_ordered_statement(s) for s in final_statements.values()),
                key=lambda statement: json.dumps(statement, sort_keys=True),
            )

        return normalize_policy(policy_res)
