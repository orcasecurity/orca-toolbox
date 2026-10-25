"""What an allow leaves after a deny, and what it keeps inside a boundary or SCP.

An allow (an `Action`) covers the resources matched by `resource` (all of them when None) except those
matched by any of `not_resources`, for requests meeting its condition. Denies are applied one after
another. A conditional deny leaves the part it covers allowed only where its condition doesn't hold; its
condition is a conjunction, so that part becomes one alternative per negated clause. Alternatives are
separate allows and are never merged back.
"""
import functools
import re
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from iam_ape.conditions import (
    Clauses,
    conjoin,
    implies,
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
    first_prefix, second_prefix = _literal_prefix(first), _literal_prefix(second)
    first_suffix, second_suffix = _literal_suffix(first), _literal_suffix(second)
    if not (
        first_prefix.startswith(second_prefix) or second_prefix.startswith(first_prefix)
    ) or not (
        first_suffix.endswith(second_suffix) or second_suffix.endswith(first_suffix)
    ):
        return ()

    memo: Dict[Tuple[int, int], FrozenSet[str]] = {}

    def common(i: int, j: int) -> FrozenSet[str]:
        """Patterns for what first[i:] and second[j:] both match."""
        if (i, j) in memo:
            return memo[(i, j)]
        if i == len(first) or j == len(second):
            rest = second[j:] if i == len(first) else first[i:]
            found = frozenset({""}) if set(rest) <= {"*"} else frozenset()
        elif first[i] == "*" and second[j] == "*":
            # whichever star stops first, the other one goes on matching
            found = frozenset(
                "*" + tail for tail in common(i + 1, j) | common(i, j + 1)
            )
        elif first[i] == "*":
            found = common(i + 1, j) | {second[j] + t for t in common(i, j + 1)}
        elif second[j] == "*":
            found = common(i, j + 1) | {first[i] + t for t in common(i + 1, j)}
        elif first[i] == second[j] or "?" in (first[i], second[j]):
            char = second[j] if first[i] == "?" else first[i]
            found = frozenset(char + tail for tail in common(i + 1, j + 1))
        else:
            found = frozenset()
        memo[(i, j)] = found
        return found

    patterns = {_collapse(p) for p in common(0, 0)}
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


def _same_scope(first: Action, second: Action) -> bool:
    return (first.resource, first.not_resources) == (
        second.resource,
        second.not_resources,
    )


def prune(actions: Iterable[Action]) -> FrozenSet[Action]:
    """Drop alternatives another one with the same resources and a weaker condition already allows."""
    unique = sorted(set(actions), key=lambda a: (len(to_clauses(a.condition)), repr(a)))
    kept: List[Action] = []
    for action in unique:
        clauses = to_clauses(action.condition)
        if not any(
            _same_scope(action, other) and implies(clauses, to_clauses(other.condition))
            for other in kept
        ):
            kept.append(action)
    return frozenset(kept)


@functools.lru_cache(maxsize=1_000_000)
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


def apply_denies(
    allow: Action, denies: Iterable[Action]
) -> Tuple[FrozenSet[Action], Optional[str]]:
    """The allow after every deny, one after another, and the deny that removed it when one did."""
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


@functools.lru_cache(maxsize=1_000_000)
def intersect(allow: Action, bound: Action) -> FrozenSet[Action]:
    """The part of the allow a boundary (or SCP) allow statement also allows."""
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
    intersect.cache_clear()
