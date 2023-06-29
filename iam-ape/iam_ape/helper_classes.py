from collections import namedtuple
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

from iam_ape.consts import PolicyElement
from iam_ape.helper_types import (
    ActionDict,
    AwsPolicyType,
    IneffectiveActionDict,
    PermissionsContainerDict,
)


class HashableList(list):
    def __hash__(self) -> int:  # type: ignore[override]
        return hash(tuple(sorted(self)))


class HashableDict(dict):
    def __hash__(self) -> int:  # type: ignore[override]
        return hash(tuple(sorted(self.items())))

    @classmethod
    def recursively(cls, dict_obj: Optional[Dict[Any, Any]]):
        if dict_obj is None:
            return None
        new_dict = {}
        for key, value in dict_obj.items():
            if isinstance(value, dict):
                new_dict[key] = cls.recursively(value)
            elif isinstance(value, list):
                new_dict[key] = HashableList(value)
            else:
                assert hasattr(value, "__hash__"), f"Unhashable type: {type(value)}"
                new_dict[key] = value
        return cls(new_dict)


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
