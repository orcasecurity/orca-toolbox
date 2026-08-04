import logging
from collections import namedtuple
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Set

from iam_ape.consts import PolicyElement
from iam_ape.helper_types import (
    ActionDict,
    AwsPolicyType,
    IneffectiveActionDict,
    PermissionsContainerDict,
)

logger = logging.getLogger("IAM-APE:cache")

# OOM safety valve for the per-account Action-holding caches (deny/expansion): the count of
# retained Action objects at which the cache clears itself. Sized well above the observed
# working set (~2 GB of caches sat far below this) so it only trips on pathological accounts.
CACHE_MAX_RETAINED_ACTIONS = 4_000_000


class CircuitBreakerCache(dict):
    """A per-account cache that clears itself once a running weight counter crosses
    ``max_weight`` — an OOM safety valve, not a working-set cap. Size it above the
    normal working set so it never trips under real load; a trip is logged because it
    means the account is large enough that the cache is thrashing, which is worth knowing.

    ``weigh`` maps a value to its contribution to the counter (Action count for the caches
    whose ``Set[Action]`` values dominate memory; defaults to 1 = entry count). Only
    whole-cache clears happen — never single-key eviction — so the counter is exact with
    add-on-insert / reset-on-clear and never needs an O(n) rescan (which would reintroduce
    the very per-insert cost a size cap is meant to avoid)."""

    def __init__(
        self,
        max_weight: int,
        weigh: Optional[Callable[[Any], int]] = None,
        name: str = "cache",
    ) -> None:
        super().__init__()
        self._max_weight = max_weight
        self._weigh = weigh
        self._weight = 0
        self._name = name

    def __setitem__(self, key: Any, value: Any) -> None:
        if key not in self:
            weight = self._weigh(value) if self._weigh is not None else 1
            if self._weight + weight > self._max_weight:
                logger.warning(
                    "%s exceeded %d; clearing (account cache is thrashing)",
                    self._name,
                    self._max_weight,
                )
                self.clear()
                self._weight = 0
            self._weight += weight
        super().__setitem__(key, value)


class HashableList(list):
    # Immutable by construction; cache the hash so these serve as cache keys cheaply.
    def __init__(self, lst: list) -> None:
        super().__init__()
        self._hash: Optional[int] = None
        for item in lst:
            if isinstance(item, dict):
                self.append(HashableDict.recursively(item))
            elif isinstance(item, list):
                self.append(HashableList(item))
            else:
                assert hasattr(item, "__hash__"), f"Unhashable type: {type(item)}"
                self.append(item)

    def __hash__(self) -> int:  # type: ignore[override]
        if self._hash is None:
            self._hash = hash(frozenset(self))
        return self._hash


class HashableDict(dict):
    # Immutable by construction; cache the hash so these serve as cache keys cheaply.
    _hash: Optional[int] = None

    def __hash__(self) -> int:  # type: ignore[override]
        if self._hash is None:
            self._hash = hash(tuple(sorted(self.items())))
        return self._hash

    @classmethod
    def recursively(cls, dict_obj: Optional[Dict[Any, Any]]):
        if dict_obj is None:
            return None
        if isinstance(dict_obj, HashableDict):
            # Already converted; skip re-wrapping on the hot path. Safe because no code
            # mutates a condition in place (shrink_policy normalizes a copy).
            return dict_obj
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
