"""A direct implementation of IAM request evaluation, used as the oracle for what iam-ape computes.

It reads policies as written and decides one request (action, resource, context) at a time, the way AWS
does: allowed when an allow statement matches and no deny statement does. iam-ape's result is checked by
deciding the same requests against the `Action`s it produced.
"""
import functools
import ipaddress
import itertools
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from iam_ape.helper_classes import Action

Context = Mapping[str, Sequence[str]]

_NEGATED = {
    "StringNotEquals",
    "StringNotEqualsIgnoreCase",
    "StringNotLike",
    "NumericNotEquals",
    "DateNotEquals",
    "NotIpAddress",
    "ArnNotEquals",
    "ArnNotLike",
}
_POSITIVE_OF = {
    "StringNotEquals": "StringEquals",
    "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
    "StringNotLike": "StringLike",
    "NumericNotEquals": "NumericEquals",
    "DateNotEquals": "DateEquals",
    "NotIpAddress": "IpAddress",
    "ArnNotEquals": "ArnEquals",
    "ArnNotLike": "ArnLike",
}


@functools.lru_cache(maxsize=100_000)
def _compiled(pattern: str, ignore_case: bool) -> "re.Pattern[str]":
    regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(regex, re.DOTALL | (re.IGNORECASE if ignore_case else 0))


def _glob(pattern: str, value: str, ignore_case: bool = False) -> bool:
    return _compiled(pattern, ignore_case).fullmatch(value) is not None


def _arn(pattern: str, value: str) -> bool:
    pattern_parts, value_parts = pattern.split(":", 5), value.split(":", 5)
    return len(pattern_parts) == len(value_parts) == 6 and all(
        _glob(p, v) for p, v in zip(pattern_parts, value_parts)
    )


def _compare(base: str, expected: str, actual: str) -> bool:
    if base == "StringEquals":
        return actual == expected
    if base == "StringEqualsIgnoreCase":
        return actual.lower() == expected.lower()
    if base == "StringLike":
        return _glob(expected, actual)
    if base == "Bool":
        return actual.lower() == expected.lower()
    if base in ("ArnEquals", "ArnLike"):
        return _arn(expected, actual)
    if base == "IpAddress":
        return ipaddress.ip_address(actual) in ipaddress.ip_network(expected)
    if base == "BinaryEquals":
        return actual == expected
    for family in ("Numeric", "Date"):
        if base.startswith(family):
            relation = base[len(family) :]  # noqa: E203
            # dates here are all written the same way, so they order as text
            key: Any = float if family == "Numeric" else str
            left, right = key(actual), key(expected)
            return {
                "Equals": left == right,
                "LessThan": left < right,
                "LessThanEquals": left <= right,
                "GreaterThan": left > right,
                "GreaterThanEquals": left >= right,
            }[relation]
    raise ValueError(f"unsupported operator {base}")


def _clause(operator: str, key: str, values: Sequence[str], context: Context) -> bool:
    qualifier, _, base = operator.rpartition(":")
    if_exists = base.endswith("IfExists")
    if if_exists:
        base = base[: -len("IfExists")]
    present = {k.lower(): v for k, v in context.items()}.get(key.lower())

    if base == "Null":
        return (present is None) == (values[0].lower() == "true")
    if present is None:
        if if_exists or qualifier == "ForAllValues":
            return True
        if qualifier == "ForAnyValue":
            return False
        return base in _NEGATED

    negated = base in _NEGATED
    positive = _POSITIVE_OF.get(base, base)

    def matches(actual: str) -> bool:
        return any(_compare(positive, expected, actual) for expected in values)

    if qualifier == "ForAllValues":
        return all(matches(a) != negated for a in present)
    if qualifier == "ForAnyValue":
        return any(matches(a) != negated for a in present)
    return matches(present[0]) != negated


def condition_holds(condition: Optional[Mapping[str, Any]], context: Context) -> bool:
    for operator, keys in (condition or {}).items():
        for key, values in keys.items():
            listed = values if isinstance(values, (list, tuple)) else [values]
            if not _clause(operator, key, [str(v) for v in listed], context):
                return False
    return True


def _listed(value: Any) -> List[str]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def statement_matches(
    statement: Mapping[str, Any], action: str, resource: str, context: Context
) -> bool:
    if "Action" in statement:
        if not any(
            _glob(p, action, ignore_case=True) for p in _listed(statement["Action"])
        ):
            return False
    elif any(
        _glob(p, action, ignore_case=True) for p in _listed(statement["NotAction"])
    ):
        return False
    if "Resource" in statement:
        if not any(_glob(p, resource) for p in _listed(statement["Resource"])):
            return False
    elif any(_glob(p, resource) for p in _listed(statement.get("NotResource"))):
        return False
    return condition_holds(statement.get("Condition"), context)


def policy_allows(
    statements: Iterable[Mapping[str, Any]],
    action: str,
    resource: str,
    context: Context,
) -> bool:
    """Whether one policy allows the request on its own: some allow matches and no deny does."""
    allowed = False
    for statement in statements:
        if statement_matches(statement, action, resource, context):
            if statement["Effect"] == "Deny":
                return False
            allowed = True
    return allowed


def denied(
    statements: Iterable[Mapping[str, Any]],
    action: str,
    resource: str,
    context: Context,
) -> bool:
    return any(
        statement["Effect"] == "Deny"
        and statement_matches(statement, action, resource, context)
        for statement in statements
    )


def actions_allow(
    actions: Iterable[Action], action: str, resource: str, context: Context
) -> bool:
    """Whether iam-ape's result for the action allows the request."""
    return any(
        a.action.lower() == action.lower()
        and _glob(a.resource or "*", resource)
        and not any(_glob(e, resource) for e in a.not_resources)
        and condition_holds(a.condition, context)
        for a in actions
    )


def contexts(candidates: Mapping[str, Sequence[Optional[Any]]]) -> List[Dict[str, Any]]:
    """Every request context made of one candidate per key; None leaves the key out."""
    keys = sorted(candidates)
    combinations: List[Dict[str, Any]] = []
    for values in itertools.product(*(candidates[k] for k in keys)):
        context: Dict[str, Any] = {}
        for key, value in zip(keys, values):
            if value is not None:
                context[key] = value if isinstance(value, list) else [value]
        combinations.append(context)
    return combinations


def condition_keys(statements: Iterable[Mapping[str, Any]]) -> Set[str]:
    return {
        key
        for statement in statements
        for keys in (statement.get("Condition") or {}).values()
        for key in keys
    }


Probe = Tuple[str, Dict[str, Any]]


def probes(
    resources: Iterable[str], candidates: Mapping[str, Sequence[Optional[Any]]]
) -> List[Probe]:
    return [(r, c) for r in resources for c in contexts(candidates)]
