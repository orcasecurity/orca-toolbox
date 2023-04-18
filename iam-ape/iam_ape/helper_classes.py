from collections import namedtuple
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from iam_ape.consts import PolicyElement
from iam_ape.helper_types import (
    ActionDict,
    AwsPolicyType,
    IneffectiveActionDict,
    PermissionsContainerDict,
)


class HashableList(List[Any]):
    def flatten(self, list_obj: List[Any]) -> List[Any]:
        all_items = []
        for item in list_obj:
            if hasattr(item, "__hash__"):
                all_items.append(item)
            elif isinstance(item, list):
                all_items.extend(self.flatten(item))
            else:
                raise TypeError(f"Unhashable type: {type(item)}")
        return all_items

    def __hash__(self) -> int:  # type: ignore[override]
        return hash(tuple(sorted(self.flatten(self))))


class HashableDict(Dict[Any, Any]):
    def __hash__(self) -> int:  # type: ignore[override]
        return hash(tuple(sorted(self.items())))

    @classmethod
    def recursively(cls, dict_obj: Optional[Dict[Any, Any]]):
        if dict_obj is None:
            return dict_obj
        for key, value in dict_obj.items():
            if isinstance(value, dict):
                dict_obj[key] = HashableDict.recursively(value)
            elif isinstance(value, list):
                dict_obj[key] = HashableList(value)
        return HashableDict(dict_obj)


@dataclass(unsafe_hash=True)
class Action:
    action: str
    resource: Optional[str]
    not_resource: Optional[str]
    condition: Optional[Dict[str, Any]]
    source: str

    def __post_init__(self) -> None:
        self.condition = HashableDict.recursively(self.condition)

    def to_dict(self) -> ActionDict:
        return {
            PolicyElement.ACTION: self.action,
            PolicyElement.RESOURCE: self.resource,
            PolicyElement.NOTRESOURCE: self.not_resource,
            PolicyElement.CONDITION: self.condition,
            "Source": self.source,
        }


@dataclass(unsafe_hash=True)
class IneffectiveAction(Action):
    denied_by: str

    def to_dict(self) -> IneffectiveActionDict:
        return {
            PolicyElement.ACTION: self.action,
            PolicyElement.RESOURCE: self.resource,
            PolicyElement.NOTRESOURCE: self.not_resource,
            PolicyElement.CONDITION: self.condition,
            "Source": self.source,
            "DeniedBy": self.denied_by,
        }


class PolicyWithSource(namedtuple("PolicyWithSource", ["source", "policy"])):
    source: str
    policy: AwsPolicyType


@dataclass
class PermissionsContainer:
    allowed_permissions: Dict[str, Set[Action]] = field(default_factory=dict)
    denied_permissions: Dict[str, Set[Action]] = field(default_factory=dict)
    ineffective_permissions: Set[IneffectiveAction] = field(default_factory=set)

    def to_dict(self) -> PermissionsContainerDict:
        res: PermissionsContainerDict = {
            "allowed_permissions": [],
            "denied_permissions": [],
            "ineffective_permissions": [],
        }
        for action_tuple_set in self.allowed_permissions.values():
            for action_tuple in action_tuple_set:
                res["allowed_permissions"].append(action_tuple.to_dict())
        for action_tuple_set in self.denied_permissions.values():
            for action_tuple in action_tuple_set:
                res["denied_permissions"].append(action_tuple.to_dict())
        for ineffective_action in self.ineffective_permissions:
            res["ineffective_permissions"].append(ineffective_action.to_dict())

        return res


@dataclass
class DenialEvalResult:
    should_deny: bool
    new_action_values: Set[Action]
    denied_by: Optional[Action]
