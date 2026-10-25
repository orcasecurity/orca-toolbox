"""IAM condition clauses: exact negation and conjunction.

A condition is a conjunction of clauses (operator, key, values). Negating a deny's condition gives a
disjunction: one alternative per clause. Each alternative is again a conjunction of clauses, so allows
stay plain IAM conditions and alternatives are kept as separate grants.

AWS evaluates a clause on a key the request doesn't carry as false, except for negated operators
(StringNotEquals, ArnNotLike, ...), `...IfExists` and `ForAllValues:` clauses, which are then true. Negation
has to preserve that, so negating a positive clause adds `IfExists` and negating `...IfExists` adds a
`Null: false` clause.
"""
import functools
from typing import Any, Dict, List, Optional, Tuple

from iam_ape.consts import CONDITIONS_NEGATIONS
from iam_ape.helper_classes import HashableDict

Clause = Tuple[str, str, Tuple[str, ...]]
Clauses = Tuple[Clause, ...]

# Operators that are true when the request doesn't carry the key
_TRUE_WHEN_ABSENT = {
    "StringNotEquals",
    "StringNotEqualsIgnoreCase",
    "StringNotLike",
    "NumericNotEquals",
    "DateNotEquals",
    "NotIpAddress",
    "ArnNotEquals",
    "ArnNotLike",
}
# Exact-match operators: two of them on one key keep the values both allow
_EXACT = {"StringEquals", "ArnEquals", "NumericEquals", "DateEquals", "BinaryEquals"}
_EXACT_IGNORE_CASE = {"StringEqualsIgnoreCase", "Bool"}
# Their negations: two of them on one key exclude the values either excludes
_EXCLUDING = {
    "StringNotEquals",
    "StringNotEqualsIgnoreCase",
    "StringNotLike",
    "ArnNotEquals",
    "ArnNotLike",
    "NumericNotEquals",
    "DateNotEquals",
    "NotIpAddress",
}
_COMPLEMENT = {
    "StringEquals": "StringNotEquals",
    "StringEqualsIgnoreCase": "StringNotEqualsIgnoreCase",
    "ArnEquals": "ArnNotEquals",
    "NumericEquals": "NumericNotEquals",
    "DateEquals": "DateNotEquals",
}


def _values(raw: Any) -> Tuple[str, ...]:
    items = raw if isinstance(raw, (list, tuple)) else [raw]
    return tuple(sorted({str(v) for v in items}))


def _parsed(condition: Dict[str, Any]) -> Clauses:
    return tuple(
        sorted(
            (operator, key, _values(values))
            for operator, keys in condition.items()
            for key, values in keys.items()
        )
    )


_parsed_cached = functools.lru_cache(maxsize=100_000)(_parsed)


def to_clauses(condition: Optional[Dict[str, Any]]) -> Clauses:
    if not condition:
        return ()
    if isinstance(condition, HashableDict):  # every Action's condition is one
        return _parsed_cached(condition)
    return _parsed(condition)


@functools.lru_cache(maxsize=100_000)
def to_condition(clauses: Clauses) -> Optional[HashableDict]:
    if not clauses:
        return None
    condition: Dict[str, Dict[str, List[str]]] = {}
    for operator, key, values in clauses:
        condition.setdefault(operator, {})[key] = list(values)
    return HashableDict.recursively(condition)


def _split(operator: str) -> Tuple[str, str, bool]:
    """(qualifier, base operator, IfExists)."""
    qualifier, _, base = operator.rpartition(":")
    if base.endswith("IfExists"):
        return qualifier, base[: -len("IfExists")], True
    return qualifier, base, False


def _flip_bool(values: Tuple[str, ...]) -> Optional[Tuple[str, ...]]:
    lowered = {v.lower() for v in values}
    if lowered == {"true"}:
        return ("false",)
    if lowered == {"false"}:
        return ("true",)
    return None


@functools.lru_cache(maxsize=100_000)
def negate(clause: Clause) -> Optional[Clauses]:
    """The conjunction that holds exactly when the clause doesn't; None when it can't be expressed."""
    operator, key, values = clause
    qualifier, base, if_exists = _split(operator)

    if base == "Null":
        flipped = _flip_bool(values)
        return ((operator, key, flipped),) if flipped and not qualifier else None

    if base == "Bool":
        if qualifier:
            return None
        flipped = _flip_bool(values)
        if flipped is None:  # true or false: holds whenever the key is there
            return (("Null", key, ("true",)),)
        if if_exists:  # absent, or the other value
            return (("Bool", key, flipped),)
        return (("BoolIfExists", key, flipped),)

    negated = CONDITIONS_NEGATIONS.get(base)
    if negated is None:
        return None

    if qualifier == "ForAnyValue" and not if_exists:
        return ((f"ForAllValues:{negated}", key, values),)
    if qualifier == "ForAllValues" and not if_exists:
        return ((f"ForAnyValue:{negated}", key, values),)
    if qualifier:
        return None

    if if_exists:  # (absent or X) negated: present and not X
        if negated in _TRUE_WHEN_ABSENT:
            return (("Null", key, ("false",)), (negated, key, values))
        return ((negated, key, values),)
    if base in _TRUE_WHEN_ABSENT or negated in _TRUE_WHEN_ABSENT:
        return ((negated, key, values),)
    # a positive operator is false when the key is absent, so its negation holds then too
    return ((f"{negated}IfExists", key, values),)


@functools.lru_cache(maxsize=100_000)
def conjoin(first: Clauses, second: Clauses) -> Optional[Clauses]:
    """Both conditions together; None when no request can meet them."""
    if not first:
        return second
    if not second:
        return first
    by_operator_key: Dict[Tuple[str, str], Tuple[str, str, Tuple[str, ...]]] = {}
    for operator, key, values in first + second:
        slot = (operator, key.lower())
        if slot not in by_operator_key:
            by_operator_key[slot] = (operator, key, values)
            continue
        _, _, existing = by_operator_key[slot]
        _, base, _ = _split(operator)
        if base in _EXACT:
            values = tuple(sorted(set(existing) & set(values)))
        elif base in _EXACT_IGNORE_CASE:
            kept = {v.lower() for v in values}
            values = tuple(sorted(v for v in existing if v.lower() in kept))
        elif base in _EXCLUDING:
            values = tuple(sorted(set(existing) | set(values)))
        elif base == "Null":
            if {v.lower() for v in existing} != {v.lower() for v in values}:
                return None
            values = existing
        else:
            # Two range or pattern clauses on one key (NumericLessThan, StringLike, IpAddress, ...) can't be
            # written as one. Keeping the first allows more than both together would: the only approximation
            # in this module, and it never removes access.
            values = existing
        if not values:
            return None
        by_operator_key[slot] = (operator, key, values)

    # A value both required and excluded on one key
    for (operator, lowered_key), (_, key, values) in list(by_operator_key.items()):
        complement = _COMPLEMENT.get(operator)
        if complement and (complement, lowered_key) in by_operator_key:
            excluded = set(by_operator_key[(complement, lowered_key)][2])
            remaining = tuple(v for v in values if v not in excluded)
            if not remaining:
                return None
            by_operator_key[(operator, lowered_key)] = (operator, key, remaining)
            del by_operator_key[(complement, lowered_key)]
    return tuple(sorted(by_operator_key.values()))


def implies(stronger: Clauses, weaker: Clauses) -> bool:
    """Whether every request meeting `stronger` meets `weaker` (judged clause by clause)."""
    return set(weaker) <= set(stronger)


def reset_caches() -> None:
    _parsed_cached.cache_clear()
    to_condition.cache_clear()
    negate.cache_clear()
    conjoin.cache_clear()
