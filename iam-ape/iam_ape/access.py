"""What an allow leaves after a deny, and what it keeps inside a boundary or SCP.

An allow (an `Action`) covers the resources matched by `resource` (all of them when None) except those
matched by any of `not_resources`, for requests meeting its condition. Denies are applied one after
another. A conditional deny leaves the part it covers allowed only where its condition doesn't hold; its
condition is a conjunction, so that part becomes one alternative per negated clause. Alternatives are
separate allows and are never merged back.
"""
import functools
import re
from collections import defaultdict
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from iam_ape.conditions import (
    Clause,
    Clauses,
    conjoin,
    negate,
    to_clauses,
    to_condition,
)
from iam_ape.helper_classes import Action

WILDCARD = "*"


@functools.lru_cache(maxsize=100_000)
def _pattern(pattern: str) -> "re.Pattern[str]":
    # `?` of the outer pattern stands for one character, never for a `*` of the inner one
    regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", "[^*]")
    return re.compile(regex, re.DOTALL)


def covers(outer: str, inner: str) -> bool:
    """Whether every resource matched by `inner` is matched by `outer`."""
    return outer == WILDCARD or _pattern(outer).fullmatch(inner) is not None


_WILDCARDS = "*?"
# Above this many patterns an intersection is approximated by the first pattern, which allows more
_MAX_PATTERNS = 16


def _collapse(pattern: str) -> str:
    while "**" in pattern:
        pattern = pattern.replace("**", "*")
    return pattern


def _literal_prefix(pattern: str) -> str:
    return re.split(r"[*?]", pattern, maxsplit=1)[0]


def _literal_suffix(pattern: str) -> str:
    return re.split(r"[*?]", pattern)[-1]


def _ends_compatible(first: str, second: str) -> bool:
    """Whether the literal text before the first and after the last wildcard lets both match one resource."""
    first_prefix, second_prefix = _literal_prefix(first), _literal_prefix(second)
    first_suffix, second_suffix = _literal_suffix(first), _literal_suffix(second)
    return (
        first_prefix.startswith(second_prefix) or second_prefix.startswith(first_prefix)
    ) and (first_suffix.endswith(second_suffix) or second_suffix.endswith(first_suffix))


class _Common:
    """Patterns for what first[i:] and second[j:] both match, memoized per (i, j)."""

    def __init__(self, first: str, second: str) -> None:
        self.first, self.second = first, second
        self.memo: Dict[Tuple[int, int], FrozenSet[str]] = {}

    def __call__(self, i: int, j: int) -> FrozenSet[str]:
        if (i, j) not in self.memo:
            self.memo[(i, j)] = self._step(i, j)
        return self.memo[(i, j)]

    def _step(self, i: int, j: int) -> FrozenSet[str]:
        first, second = self.first, self.second
        if i == len(first) or j == len(second):
            rest = second[j:] if i == len(first) else first[i:]
            return frozenset({""}) if set(rest) <= {"*"} else frozenset()
        a, b = first[i], second[j]
        if a == "*" and b == "*":
            # whichever star stops first, the other one goes on matching
            return frozenset("*" + t for t in self(i + 1, j) | self(i, j + 1))
        if a == "*":
            return self(i + 1, j) | {b + t for t in self(i, j + 1)}
        if b == "*":
            return self(i, j + 1) | {a + t for t in self(i + 1, j)}
        if a == b or "?" in (a, b):
            char = b if a == "?" else a
            return frozenset(char + t for t in self(i + 1, j + 1))
        return frozenset()


@functools.lru_cache(maxsize=100_000)
def intersection(first: str, second: str) -> Tuple[str, ...]:
    """Patterns matching exactly the resources both match; empty when none does."""
    if covers(first, second):
        return (second,)
    if covers(second, first):
        return (first,)
    if not any(c in first for c in _WILDCARDS) or not any(
        c in second for c in _WILDCARDS
    ):
        return ()
    if not _ends_compatible(first, second):
        return ()
    patterns = {_collapse(p) for p in _Common(first, second)(0, 0)}
    kept = sorted(
        p for p in patterns if not any(o != p and covers(o, p) for o in patterns)
    )
    return tuple(kept) if len(kept) <= _MAX_PATTERNS else (first,)


def disjoint(first: str, second: str) -> bool:
    """Whether no resource matches both."""
    return not intersection(first, second)


def _resource(action: Action) -> str:
    return action.resource or WILDCARD


def _scoped(
    action: Action, resource: str, not_resources: Iterable[str], clauses: Clauses
) -> Optional[Action]:
    """The allow narrowed to `resource` minus `not_resources`; None when nothing is left."""
    kept: List[str] = []
    for excluded in sorted(set(not_resources)):
        if covers(excluded, resource):
            return None
        if not disjoint(excluded, resource):
            kept.append(excluded)
    kept = [e for e in kept if not any(o != e and covers(o, e) for o in kept)]
    return Action(
        action=action.action,
        resource=None if resource == WILDCARD and kept else resource,
        not_resources=tuple(kept),
        condition=to_condition(clauses),
        source=action.source,
    )


def order_key(action: Action) -> Tuple[Any, ...]:
    """A total order on actions, weakest condition first."""
    clauses = to_clauses(action.condition)
    return (
        len(clauses),
        clauses,
        action.resource or "",
        action.not_resources,
        action.source,
    )


def prune(actions: Iterable[Action]) -> FrozenSet[Action]:
    """Drop alternatives another one with the same resources and a weaker condition already allows."""
    distinct = set(actions)
    if len(distinct) < 2:
        return frozenset(distinct)
    by_scope: Dict[Tuple[Optional[str], Tuple[str, ...]], List[Action]] = defaultdict(
        list
    )
    for action in distinct:
        by_scope[(action.resource, action.not_resources)].append(action)
    kept: List[Action] = []
    for scoped in by_scope.values():
        weaker: List[FrozenSet[Clause]] = []
        for action in sorted(scoped, key=order_key):
            clauses = frozenset(to_clauses(action.condition))
            if not any(condition <= clauses for condition in weaker):
                weaker.append(clauses)
                kept.append(action)
    return frozenset(kept)


def _template(action: Action, source: str = "") -> Action:
    """The action's scope and condition alone: what subtracting and intersecting depend on."""
    return Action("", action.resource, action.not_resources, action.condition, source)


def _instantiate(templates: Iterable[Action], action: Action) -> FrozenSet[Action]:
    return frozenset(
        Action(action.action, t.resource, t.not_resources, t.condition, action.source)
        for t in templates
    )


@functools.lru_cache(maxsize=200_000)
def subtract(allow: Action, deny: Action) -> Optional[FrozenSet[Action]]:
    """What's left of the allow after the deny; None when the deny can't touch it."""
    allowed, denied = _resource(allow), _resource(deny)
    covered = intersection(allowed, denied)
    if not covered:
        return None
    allow_clauses = to_clauses(allow.condition)
    left: List[Optional[Action]] = []

    # resources the deny doesn't name
    if not covers(denied, allowed):
        left.append(
            _scoped(allow, allowed, allow.not_resources + (denied,), allow_clauses)
        )

    # resources the deny names but excepts with NotResource
    for excepted in deny.not_resources:
        for resource in covered:
            for kept in intersection(resource, excepted):
                left.append(_scoped(allow, kept, allow.not_resources, allow_clauses))

    # resources the deny covers, for requests its condition doesn't apply to
    excluded = allow.not_resources + deny.not_resources
    for clause in to_clauses(deny.condition):
        negation = negate(clause)
        clauses = (
            allow_clauses  # when the deny doesn't apply can't be written: keep the allow there
            if negation is None
            else conjoin(allow_clauses, negation)
        )
        if clauses is not None:
            left.extend(
                _scoped(allow, resource, excluded, clauses) for resource in covered
            )

    remaining = prune(a for a in left if a is not None)
    return None if remaining == frozenset({allow}) else remaining


Denies = Tuple[Action, ...]


def prepare_denies(denies: Iterable[Action]) -> Denies:
    """The denies of one action in the order they're applied, without the action itself."""
    return tuple(_template(d, d.source) for d in sorted(denies, key=order_key))


def apply_denies(
    allow: Action, denies: Denies
) -> Tuple[FrozenSet[Action], Optional[str]]:
    """The allow after every deny, one after another, and the deny that removed it when one did."""
    remaining, denied_by = _apply_denies(_template(allow), denies)
    return _instantiate(remaining, allow), denied_by


@functools.lru_cache(maxsize=200_000)
def _apply_denies(
    allow: Action, denies: Denies
) -> Tuple[FrozenSet[Action], Optional[str]]:
    current: FrozenSet[Action] = frozenset({allow})
    for deny in denies:
        following: Set[Action] = set()
        for action in current:
            remaining = subtract(action, deny)
            following |= {action} if remaining is None else remaining
        if not following:
            return frozenset(), deny.source
        current = prune(following)
    return current, None


def intersect(allow: Action, bound: Action) -> FrozenSet[Action]:
    """The part of the allow a boundary (or SCP) allow statement also allows."""
    return _instantiate(_intersect(_template(allow), _template(bound)), allow)


@functools.lru_cache(maxsize=200_000)
def _intersect(allow: Action, bound: Action) -> FrozenSet[Action]:
    clauses = conjoin(to_clauses(allow.condition), to_clauses(bound.condition))
    if clauses is None:
        return frozenset()
    kept = (
        _scoped(allow, resource, allow.not_resources + bound.not_resources, clauses)
        for resource in intersection(_resource(allow), _resource(bound))
    )
    return frozenset(a for a in kept if a is not None)


def is_unrestricted(bound: Action) -> bool:
    return (
        not bound.condition and not bound.not_resources and _resource(bound) == WILDCARD
    )


def reset_caches() -> None:
    _pattern.cache_clear()
    intersection.cache_clear()
    subtract.cache_clear()
    _apply_denies.cache_clear()
    _intersect.cache_clear()
