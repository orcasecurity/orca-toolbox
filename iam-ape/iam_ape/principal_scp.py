import json
from collections import defaultdict
from fnmatch import fnmatchcase
from typing import Any, Dict, List, Optional, Set, Tuple

from iam_ape.helper_classes import Action, PermissionsContainer, PolicyWithSource
from iam_ape.helper_types import EntityType

PRINCIPAL_KEYS = frozenset(
    {
        "aws:principalarn",
        "aws:principalaccount",
        "aws:principalorgid",
        "aws:principalorgpaths",
        "aws:principaltype",
        "aws:principalisawsservice",
    }
)
TAG_PREFIX = "aws:principaltag/"
SERVICE_LINKED_PATH = "/aws-service-role/"


def is_principal_key(key: str) -> bool:
    key = key.lower()
    return key in PRINCIPAL_KEYS or key.startswith(TAG_PREFIX)


def can_tag_session(entity: Dict[str, Any]) -> bool:
    trust = entity.get("AssumeRolePolicyDocument") or {}
    statements = trust.get("Statement", [])
    for statement in statements if isinstance(statements, list) else [statements]:
        actions = statement.get("Action", [])
        for action in actions if isinstance(actions, list) else [actions]:
            if fnmatchcase("sts:tagsession", str(action).lower()):
                return True
    return False


def principal_values(
    arn: str,
    entity: Dict[str, Any],
    entity_type: EntityType,
    org_id: Optional[str],
    org_path: Optional[str],
) -> Optional[Dict[str, List[str]]]:
    """What a request from this principal carries in its principal keys; None for a group."""
    if entity_type not in (EntityType.role, EntityType.user):
        return None
    values: Dict[str, List[str]] = {
        "aws:principalarn": [arn],
        "aws:principalaccount": [arn.split(":")[4]],
        "aws:principaltype": ["AssumedRole" if entity_type == EntityType.role else "User"],
        "aws:principalisawsservice": ["false"],
    }
    if org_id:
        values["aws:principalorgid"] = [org_id]
    if org_path:
        values["aws:principalorgpaths"] = [org_path]
    if not (entity_type == EntityType.role and can_tag_session(entity)):
        for tag in entity.get("Tags", []) or []:
            values[TAG_PREFIX + str(tag.get("Key")).lower()] = [str(tag.get("Value"))]
        values["__tags_known__"] = ["true"]
    return values


def _matches(base: str, value: str, patterns: List[str]) -> bool:
    if base in ("StringLike", "ArnLike", "StringNotLike", "ArnNotLike"):
        return any(fnmatchcase(value, p) for p in patterns)
    if base in ("StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"):
        return value.lower() in {p.lower() for p in patterns}
    if base == "Bool":
        return value.lower() in {p.lower() for p in patterns}
    return value in patterns


_POSITIVE = {"StringEquals", "StringLike", "ArnEquals", "ArnLike", "StringEqualsIgnoreCase", "Bool"}
_NEGATED = {"StringNotEquals", "StringNotLike", "ArnNotEquals", "ArnNotLike", "StringNotEqualsIgnoreCase"}


def decide_clause(operator: str, key: str, policy_values: Any, values: Dict[str, List[str]]) -> Optional[bool]:
    """True/False when the principal decides the clause, None when only the request can."""
    key = key.lower()
    patterns = [str(v) for v in (policy_values if isinstance(policy_values, list) else [policy_values])]
    qualifier, _, base = operator.rpartition(":")
    if_exists = base.endswith("IfExists")
    base = base[: -len("IfExists")] if if_exists else base
    present = values.get(key)
    if present is None:
        if key.startswith(TAG_PREFIX) and "__tags_known__" in values:
            if base == "Null":
                return "true" in [p.lower() for p in patterns]
            return True if if_exists else None
        return None
    if base == "Null":
        return "false" in [p.lower() for p in patterns]
    if base in _POSITIVE:
        results = [_matches(base, v, patterns) for v in present]
    elif base in _NEGATED:
        results = [not _matches(base, v, patterns) for v in present]
    else:
        return None
    if qualifier == "ForAllValues":
        return all(results)
    return any(results)


def resolve_statement(statement: Dict[str, Any], values: Dict[str, List[str]]) -> Optional[Dict[str, Any]]:
    """The deny as it applies to this principal: None if it doesn't, else with only the clauses the request decides."""
    remaining: Dict[str, Dict[str, Any]] = defaultdict(dict)
    for operator, keys in (statement.get("Condition") or {}).items():
        for key, policy_values in keys.items():
            decided = decide_clause(operator, key, policy_values, values) if is_principal_key(key) else None
            if decided is False:
                return None
            if decided is None:
                remaining[operator][key] = policy_values
    resolved = {k: v for k, v in statement.items() if k != "Condition"}
    if remaining:
        resolved["Condition"] = dict(remaining)
    return resolved


def merge_containers(base: PermissionsContainer, extra: PermissionsContainer) -> PermissionsContainer:
    allowed: Dict[str, Set[Action]] = defaultdict(set)
    denied: Dict[str, Set[Action]] = defaultdict(set)
    for container in (base, extra):
        for key, actions in container.allowed_permissions.items():
            allowed[key] |= set(actions)
        for key, actions in container.denied_permissions.items():
            denied[key] |= set(actions)
    return PermissionsContainer(allowed_permissions=allowed, denied_permissions=denied)


class ScpLevel:
    """One level of the organization (root, an OU, the account): the principal must be allowed by it."""

    def __init__(self, policies: List[PolicyWithSource], expander: Any) -> None:
        self.expander = expander
        static: List[PolicyWithSource] = []
        self.conditional: List[Tuple[str, Dict[str, Any]]] = []
        for policy in policies:
            statements = policy.policy.get("Statement", [])
            kept = []
            for statement in statements if isinstance(statements, list) else [statements]:
                condition = statement.get("Condition") or {}
                if statement.get("Effect") == "Deny" and any(
                    is_principal_key(key) for keys in condition.values() for key in keys
                ):
                    self.conditional.append((policy.source, statement))
                else:
                    kept.append(statement)
            if kept:
                static.append(PolicyWithSource(policy.source, {**policy.policy, "Statement": kept}))
        self.static = expander.expand_policies(static) if static else PermissionsContainer()
        self._by_outcome: Dict[str, PermissionsContainer] = {}

    def for_principal(self, values: Optional[Dict[str, List[str]]]) -> PermissionsContainer:
        if not self.conditional:
            return self.static
        resolved = [
            (source, statement if values is None else resolve_statement(statement, values))
            for source, statement in self.conditional
        ]
        resolved = [(source, statement) for source, statement in resolved if statement is not None]
        key = json.dumps(resolved, sort_keys=True, default=str)
        if key not in self._by_outcome:
            extra = (
                self.expander.expand_policies(
                    [PolicyWithSource(source, {"Version": "2012-10-17", "Statement": [s]}) for source, s in resolved]
                )
                if resolved
                else PermissionsContainer()
            )
            self._by_outcome[key] = merge_containers(self.static, extra) if resolved else self.static
        return self._by_outcome[key]
