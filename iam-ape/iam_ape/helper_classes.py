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

# Size ceiling for the expansion cache (retained-Action count at which it stops accepting new
# keys). Sized from the MEASURED transitive footprint (tracemalloc): a condition-free expansion
# Action is ~300 B, so 1 M entries is ~300 MB — a fraction of the clouder pod. Reaching the cap
# degrades the cache to uncached, never the scan to failure. Tune against measured hit-rate-vs-cap.
EXPANSION_CACHE_MAX_WEIGHT = 1_000_000  # ~300 MB at ~300 B / condition-free Action


class CappedMemoCache(dict):
    """A memo with a hard weight ceiling: once inserting a *new* key would exceed ``max_weight``
    that key is skipped (recomputed on the next lookup) instead of stored. Every use here is a
    pure memo — recompute-on-miss yields the same value — so refusing inserts at the cap is
    correctness-neutral and degrades gracefully to "uncached beyond the cap", while the hot,
    shared early entries stay cached. Deliberately not clear-on-overflow, which would repeatedly
    discard those hot entries and pay to rebuild them (measured ~+18% wall on btg).

    ``weigh`` maps a value to its weight (default 1 = entry count; the expansion cache weighs by
    retained Action count so a cap bounds bytes, not entries). Callers insert each key once and
    never overwrite, so the counter is monotonic (add-on-accepted-insert, reset only by clear());
    an overwrite would leave it unchanged — a benign under-count the insert-once contract rules
    out. Reaching the cap is logged once (the account is running partially uncached)."""

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
        self._capped = False

    def __setitem__(self, key: Any, value: Any) -> None:
        if key not in self:
            weight = self._weigh(value) if self._weigh is not None else 1
            if self._weight + weight > self._max_weight:
                if not self._capped:
                    self._capped = True
                    logger.warning(
                        "%s reached its %d-weight cap; account running partially uncached",
                        self._name,
                        self._max_weight,
                    )
                return
            self._weight += weight
        super().__setitem__(key, value)

    def clear(self) -> None:
        super().clear()
        self._weight = 0
        self._capped = False


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
