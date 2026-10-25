"""Service control policies applied one organization level at a time.

A principal is allowed an action only if every level (root, each OU, the account) allows it, and a deny at
any level denies it. Deny statements whose conditions test the principal itself (its ARN, account,
organization, type or tags) are decided per principal: a false clause means the deny doesn't apply to it,
true clauses are dropped, and only the clauses about the request are kept as a condition.
"""
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, cast

from iam_ape.helper_classes import PermissionsContainer, PolicyWithSource
from iam_ape.helper_types import AwsPolicyStatementType, EntityType

SERVICE_LINKED_ROLE_PATH = "/aws-service-role/"
PRINCIPAL_TAG_PREFIX = "aws:principaltag/"
PRINCIPAL_KEYS = frozenset(
    {
        "aws:principalarn",
        "aws:principalaccount",
        "aws:principalorgid",
        "aws:principalorgpaths",
        "aws:principaltype",
        "aws:principalisawsservice",
        "aws:username",
        "aws:userid",
    }
)

_STRING_EQUALS = {"StringEquals", "ArnEquals", "Bool", "StringEqualsIgnoreCase"}
_STRING_LIKE = {"StringLike", "ArnLike"}
_NEGATED = {
    "StringNotEquals": "StringEquals",
    "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
    "StringNotLike": "StringLike",
    "ArnNotEquals": "ArnEquals",
    "ArnNotLike": "ArnLike",
}


def is_principal_key(key: str) -> bool:
    key = key.lower()
    return key in PRINCIPAL_KEYS or key.startswith(PRINCIPAL_TAG_PREFIX)


def is_service_linked_role(entity: Dict[str, Any], entity_type: EntityType) -> bool:
    return entity_type == EntityType.role and entity.get("Path", "").startswith(
        SERVICE_LINKED_ROLE_PATH
    )


@dataclass(frozen=True)
class Principal:
    """The values a request from this user or role carries in its principal condition keys.

    `values` maps a lowercased key to its values; a key that is missing is absent from every request,
    except the ones listed in `undecided`, whose value depends on how the request is made.
    """

    values: Dict[str, Tuple[str, ...]]
    undecided: Tuple[str, ...]

    @classmethod
    def of(
        cls,
        arn: str,
        entity: Dict[str, Any],
        entity_type: EntityType,
        org_id: Optional[str] = None,
        org_path: Optional[str] = None,
    ) -> Optional["Principal"]:
        """None for a group: groups aren't principals, so nothing about them can be decided."""
        if entity_type not in (EntityType.user, EntityType.role):
            return None
        values: Dict[str, Tuple[str, ...]] = {
            "aws:principalarn": (arn,),
            "aws:principalaccount": (arn.split(":")[4],),
            "aws:principalisawsservice": ("false",),
        }
        undecided: List[str] = []
        if entity_type == EntityType.user:
            values["aws:principaltype"] = ("User",)
            values["aws:username"] = (entity.get("UserName", arn.split("/")[-1]),)
            if entity.get("UserId"):
                values["aws:userid"] = (entity["UserId"],)
        else:
            values["aws:principaltype"] = ("AssumedRole",)
            undecided.append(
                "aws:userid"
            )  # the role's id followed by the caller's session name
        if org_id:
            values["aws:principalorgid"] = (org_id,)
        else:
            undecided.append("aws:principalorgid")
        if org_path:
            values["aws:principalorgpaths"] = (org_path,)
        else:
            undecided.append("aws:principalorgpaths")
        if entity_type == EntityType.role and _allows_session_tags(entity):
            undecided.append(PRINCIPAL_TAG_PREFIX)
        else:
            for tag in entity.get("Tags") or []:
                values[PRINCIPAL_TAG_PREFIX + str(tag.get("Key")).lower()] = (
                    str(tag.get("Value")),
                )
        return cls(values=values, undecided=tuple(undecided))

    def is_undecided(self, key: str) -> bool:
        return any(
            key == u or (u.endswith("/") and key.startswith(u)) for u in self.undecided
        )


def _allows_session_tags(role: Dict[str, Any]) -> bool:
    """A role whose trust policy allows sts:TagSession can be assumed with session tags that override its own."""
    statements = (role.get("AssumeRolePolicyDocument") or {}).get("Statement", [])
    for statement in statements if isinstance(statements, list) else [statements]:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        for action in actions if isinstance(actions, list) else [actions]:
            if _glob_match("sts:tagsession", str(action).lower()):
                return True
    return False


def _glob_match(value: str, pattern: str) -> bool:
    """AWS wildcards: `*` any run of characters, `?` one character; nothing else is special."""
    regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(regex, value, flags=re.DOTALL) is not None


def _is_arn_pattern(pattern: str) -> bool:
    return pattern == "*" or len(pattern.split(":", 5)) == 6


def _arn_match(value: str, pattern: str) -> bool:
    """ArnLike: each of the six colon-separated ARN fields is matched on its own."""
    if pattern == "*":
        return True
    return all(
        _glob_match(v, p) for v, p in zip(value.split(":", 5), pattern.split(":", 5))
    )


def _matches(base: str, value: str, policy_values: Iterable[str]) -> bool:
    if base == "ArnLike":
        return any(_arn_match(value, p) for p in policy_values)
    if base == "StringLike":
        return any(_glob_match(value, p) for p in policy_values)
    if base in ("StringEqualsIgnoreCase", "Bool"):
        return value.lower() in {p.lower() for p in policy_values}
    return value in set(policy_values)


def decide_clause(
    operator: str, key: str, policy_values: Any, principal: Principal
) -> Optional[bool]:
    """Whether a clause on a principal key holds for every request from this principal; None if it depends
    on the request (or on an operator this module doesn't model)."""
    key = key.lower()
    if principal.is_undecided(key):
        return None
    qualifier, _, base = operator.rpartition(":")
    if_exists = base.endswith("IfExists")
    base = base[: -len("IfExists")] if if_exists else base
    expected = [
        str(v)
        for v in (policy_values if isinstance(policy_values, list) else [policy_values])
    ]
    present = principal.values.get(key)

    if base == "Null":
        return (present is None) == ("true" in [v.lower() for v in expected])
    negated = base in _NEGATED
    base = _NEGATED.get(base, base)
    if base not in _STRING_EQUALS and base not in _STRING_LIKE:
        return None
    if base == "ArnLike" and not all(_is_arn_pattern(v) for v in expected):
        return None
    if present is None:
        if if_exists or qualifier == "ForAllValues":
            return True
        if qualifier == "ForAnyValue":
            return False
        return negated
    results = [_matches(base, value, expected) != negated for value in present]
    return all(results) if qualifier == "ForAllValues" else any(results)


def deny_for_principal(
    statement: AwsPolicyStatementType, principal: Optional[Principal]
) -> Optional[AwsPolicyStatementType]:
    """The deny as it applies to this principal: None when it can't apply, otherwise the statement with
    only the clauses the principal doesn't decide. A group (no principal) keeps every clause."""
    if principal is None:
        return statement
    remaining: Dict[str, Dict[str, Any]] = {}
    for operator, keys in (statement.get("Condition") or {}).items():
        for key, policy_values in keys.items():
            decided = (
                decide_clause(operator, key, policy_values, principal)
                if is_principal_key(key)
                else None
            )
            if decided is False:
                return None
            if decided is None:
                remaining.setdefault(operator, {})[key] = policy_values
    resolved = cast(AwsPolicyStatementType, dict(statement))
    resolved.pop("Condition", None)
    if remaining:
        resolved["Condition"] = remaining
    return resolved


def _union(containers: Iterable[PermissionsContainer]) -> PermissionsContainer:
    union = PermissionsContainer(allowed_permissions={}, denied_permissions={})
    for container in containers:
        for target, source in (
            (union.allowed_permissions, container.allowed_permissions),
            (union.denied_permissions, container.denied_permissions),
        ):
            for action, actions in source.items():
                target.setdefault(action, set()).update(actions)
    return union


class ScpLevel:
    """The SCPs attached to one target (root, OU or account), expanded once and specialized per principal."""

    def __init__(self, policies: List[PolicyWithSource], expander: Any) -> None:
        self._expander = expander
        static: List[PolicyWithSource] = []
        self._per_principal: List[Tuple[str, AwsPolicyStatementType]] = []
        for policy in policies:
            kept: List[AwsPolicyStatementType] = []
            for statement in policy.policy.get("Statement", []):
                if statement.get("Effect") == "Deny" and any(
                    is_principal_key(key)
                    for keys in (statement.get("Condition") or {}).values()
                    for key in keys
                ):
                    self._per_principal.append((policy.source, statement))
                else:
                    kept.append(statement)
            if kept:
                static.append(
                    PolicyWithSource(
                        policy.source, {**policy.policy, "Statement": kept}
                    )
                )
        self._static = (
            expander.expand_policies(static) if static else PermissionsContainer()
        )
        self._statements: Dict[str, PermissionsContainer] = {}
        self._combinations: Dict[Tuple[str, ...], PermissionsContainer] = {}

    def for_principal(self, principal: Optional[Principal]) -> PermissionsContainer:
        if not self._per_principal:
            return self._static
        keys: List[str] = []
        for source, statement in self._per_principal:
            resolved = deny_for_principal(statement, principal)
            if resolved is None:
                continue
            key = json.dumps([source, resolved], sort_keys=True, default=str)
            if key not in self._statements:
                self._statements[key] = self._expander.expand_policies(
                    [
                        PolicyWithSource(
                            source, {"Version": "2012-10-17", "Statement": [resolved]}
                        )
                    ]
                )
            keys.append(key)
        if not keys:
            return self._static
        combination = tuple(keys)
        if combination not in self._combinations:
            self._combinations[combination] = _union(
                [self._static, *(self._statements[k] for k in keys)]
            )
        return self._combinations[combination]
