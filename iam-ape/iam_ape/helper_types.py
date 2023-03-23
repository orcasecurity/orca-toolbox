from collections import namedtuple
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, TypedDict

from iam_ape.consts import PolicyElement


class FinalReportT(TypedDict):
    allowed_permissions: Dict[
        str,
        Dict[
            str,
            Dict[
                str,
                Dict[
                    str,
                    Dict[str, Optional[Dict[str, Any]]],
                ],
            ],
        ],
    ]
    denied_permissions: Dict[
        str,
        Dict[
            str,
            Dict[
                str,
                Dict[
                    str,
                    Dict[str, Optional[Dict[str, Any]]],
                ],
            ],
        ],
    ]
    ineffective_permissions: Dict[
        str, Dict[str, Dict[str, Dict[str, Dict[str, Set[str]]]]]
    ]


class AwsPolicyStatementType(TypedDict, total=False):
    Effect: str
    Sid: Optional[str]
    Action: Optional[List[str]]
    NotAction: Optional[List[str]]
    Resource: Optional[List[str]]
    NotResource: Optional[List[str]]
    Principal: Optional[Dict[str, Any]]
    NotPrincipal: Optional[Dict[str, Any]]
    Condition: Optional[Dict[str, Any]]


class AwsPolicyType(TypedDict, total=False):
    Version: Optional[str]
    Id: Optional[str]
    Statement: List[AwsPolicyStatementType]


class EntityType(Enum):
    user: str = "User"
    group: str = "Group"
    role: str = "Role"


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


class ActionDict(TypedDict):
    Action: str
    Resource: Optional[str]
    NotResource: Optional[str]
    Condition: Optional[Dict[str, Any]]
    Source: str


class IneffectiveActionDict(ActionDict):
    DeniedBy: str


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


class PermissionsContainerDict(TypedDict):
    allowed_permissions: List[ActionDict]
    denied_permissions: List[ActionDict]
    ineffective_permissions: List[ActionDict]


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
