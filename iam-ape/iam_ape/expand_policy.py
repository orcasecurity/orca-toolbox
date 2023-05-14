import json
import logging
import tarfile
from collections import defaultdict
from fnmatch import fnmatch
from typing import Any, Dict, FrozenSet, List, Literal, Optional, Set, Tuple

from requests.structures import CaseInsensitiveDict

from iam_ape.consts import RESOURCE_ARN_RE, PolicyElement, actions_json_location
from iam_ape.helper_classes import (
    Action,
    HashableDict,
    HashableList,
    PermissionsContainer,
    PolicyWithSource,
)
from iam_ape.helper_functions import as_list, normalize_policy
from iam_ape.helper_types import AwsPolicyStatementType, AwsPolicyType

logger = logging.getLogger("policy expander")


def _append_action(
    res: Dict[str, Set[Action]],
    action: str,
    service: str,
    resources: Optional[List[str]],
    not_resources: Optional[List[str]],
    condition: Optional[Dict[str, Any]],
    source: str,
) -> None:
    def relevant_resource(resource: str, service: str) -> bool:
        if resource.lower() in (
            "*",
            "arn:*",
            "arn:aws:*",
            "arn:aws-gov:*",
            "arn:aws-china:*",
        ):
            return True
        if match := RESOURCE_ARN_RE.match(resource):
            res_service = match.group("service")
            return res_service.lower() == service.lower()
        return False

    for resource in resources or []:
        if not relevant_resource(resource, service):
            continue
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
    for not_resource in not_resources or []:
        if not relevant_resource(not_resource, service):
            continue
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
                            fnmatch(curr_action_lower, not_action.lower())
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

    def get_action_access_level(self, action: str) -> str:
        service, action_key = action.split(":", maxsplit=1)
        return self.all_iam_actions[service][action_key]["access"]

    def deflate_policy_statements(
        self,
        policy_statements: List[AwsPolicyStatementType],
    ) -> List[AwsPolicyStatementType]:
        for statement in policy_statements:
            action_dict = defaultdict(list)
            for action in statement.get(PolicyElement.ACTION) or []:
                service, action_key = action.split(":", maxsplit=1)
                action_dict[service].append(action_key)
            for service, action_keys in action_dict.items():
                try:
                    if all(
                        [
                            action in action_keys
                            for action in self.all_iam_actions[service]
                        ]
                    ):
                        for action_key in action_keys:
                            statement[PolicyElement.ACTION].remove(f"{service}:{action_key}")  # type: ignore
                        statement[PolicyElement.ACTION].append(f"{service}:*")  # type: ignore
                except KeyError as e:
                    logger.exception(f"Unknown service: {service=}")
                    raise e
            if all(
                [
                    action in as_list(statement[PolicyElement.ACTION])
                    for action in self._all_service_wildcards
                ]
            ):
                statement[PolicyElement.ACTION] = ["*"]
        return policy_statements

    def shrink_policy(self, allow_actions: Dict[str, Set[Action]]) -> AwsPolicyType:
        policy_res: AwsPolicyType = {"Statement": []}
        squashed_policies: Set[Action] = set()
        for allow_action_set in allow_actions.values():
            squashed_policies.update(allow_action_set)

        # Arrange by Resource/NotResource
        by_resource_notresource: Dict[
            Tuple[Optional[str], Optional[str]], Dict[Optional[HashableDict], Set[str]]
        ] = defaultdict(lambda: defaultdict(set))
        for action_tuple in squashed_policies:
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
                key = frozenset(actions_set), condition, notresource
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
                    final_statements[statement_key][PolicyElement.RESOURCE] = list(
                        set(rsrc)
                    )
                not_rsrc = (
                    final_statements[statement_key].get(PolicyElement.NOTRESOURCE) or []
                ) + (statement.get(PolicyElement.NOTRESOURCE) or [])
                if not_rsrc:
                    final_statements[statement_key][PolicyElement.NOTRESOURCE] = list(
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
            policy_res["Statement"] = list(final_statements.values())

        return normalize_policy(policy_res)
