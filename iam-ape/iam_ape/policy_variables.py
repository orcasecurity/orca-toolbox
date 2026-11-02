"""Policy variables (`${aws:username}`, `${aws:PrincipalTag/team}`, ...) resolved for one principal.

A variable the principal decides is replaced by its value (or by the `${key, 'default'}` default when the
principal doesn't have the key). A resource whose variable the principal decides to be absent matches
nothing. Variables that depend on the request (or on a session) are left as they are.
"""
import json
import re
from typing import Any, Dict, List, Optional, Union, cast

from iam_ape.helper_classes import PolicyWithSource
from iam_ape.helper_types import AwsPolicyStatementType
from iam_ape.principal_scp import Principal, is_principal_key

VARIABLE = re.compile(r"\$\{([^}]*)\}")
_LITERALS = {"*": "*", "?": "?", "$": "$"}


class _MatchesNothing(Exception):
    pass


def has_variables(document: Any) -> bool:
    return "${" in json.dumps(document)


def resolve(value: str, principal: Principal) -> Optional[str]:
    """The value with every variable the principal decides substituted; None when it matches nothing."""
    if "${" not in value:
        return value

    def substitute(match: "re.Match[str]") -> str:
        key, _, default = match.group(1).partition(",")
        key = key.strip()
        if key in _LITERALS:
            return _LITERALS[key]
        lowered = key.lower()
        if lowered in principal.values:
            return principal.values[lowered][0]
        default = default.strip()
        if len(default) >= 2 and default[0] == default[-1] == "'":
            return default[1:-1]
        if is_principal_key(lowered) and not principal.is_undecided(lowered):
            raise _MatchesNothing
        return match.group(0)

    try:
        return VARIABLE.sub(substitute, value)
    except _MatchesNothing:
        return None


def _resolved_list(values: Union[str, List[str]], principal: Principal) -> List[str]:
    resolved = [
        resolve(v, principal)
        for v in (values if isinstance(values, list) else [values])
    ]
    return [v for v in resolved if v is not None]


def _resolved_condition_value(value: Any, principal: Principal) -> Any:
    # a value that matches nothing for this principal is left as written
    if not isinstance(value, str):
        return value
    resolved = resolve(value, principal)
    return value if resolved is None else resolved


def _resolved_condition(
    condition: Dict[str, Dict[str, Any]], principal: Principal
) -> Dict[str, Dict[str, Any]]:
    return {
        operator: {
            key: [
                _resolved_condition_value(v, principal)
                for v in (values if isinstance(values, list) else [values])
            ]
            for key, values in keys.items()
        }
        for operator, keys in condition.items()
    }


def _resolved_statement(
    statement: AwsPolicyStatementType, principal: Principal
) -> Optional[AwsPolicyStatementType]:
    resolved = cast(AwsPolicyStatementType, dict(statement))
    if statement.get("Resource"):
        resources = _resolved_list(statement["Resource"] or [], principal)
        if not resources:
            return None  # every resource it names matches nothing for this principal
        resolved["Resource"] = resources
    if statement.get("NotResource"):
        not_resources = _resolved_list(statement["NotResource"] or [], principal)
        if not_resources:
            resolved["NotResource"] = not_resources
        else:  # excludes nothing
            resolved.pop("NotResource")
            resolved["Resource"] = ["*"]
    if statement.get("Condition"):
        resolved["Condition"] = _resolved_condition(
            statement["Condition"] or {}, principal
        )
    return resolved


def for_principal(
    policy: PolicyWithSource, principal: Optional[Principal]
) -> PolicyWithSource:
    """The policy as it reads for this principal. Groups (no principal) keep their variables."""
    if principal is None or not policy.policy or not has_variables(policy.policy):
        return policy
    statements = [
        resolved
        for statement in policy.policy.get("Statement", [])
        if (resolved := _resolved_statement(statement, principal)) is not None
    ]
    return PolicyWithSource(policy.source, {**policy.policy, "Statement": statements})
