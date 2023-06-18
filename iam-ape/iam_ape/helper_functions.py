import logging
from fnmatch import fnmatch
from typing import Any, Dict, List, Literal, Optional, Set, TypeVar

from iam_ape.consts import CONDITIONS_NEGATIONS
from iam_ape.helper_classes import HashableDict, HashableList
from iam_ape.helper_types import AwsPolicyType

logger = logging.getLogger(__name__)

KeyType = TypeVar("KeyType")


def as_list(element: Optional[Any]) -> List[Any]:
    if not element:
        return []
    if isinstance(element, list):
        return element
    return [element]


def normalize_policy(policy: AwsPolicyType) -> AwsPolicyType:
    def verify_type(subject: Any, subject_type: Any, err_msg: str) -> None:
        if not isinstance(subject, subject_type):
            raise TypeError(err_msg)

    def normalize_dict(
        dict_to_norm: Dict[str, Any], fields: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        for field in fields or set(dict_to_norm.keys()):
            if not isinstance(dict_to_norm.get(field, []), list):
                dict_to_norm[field] = [dict_to_norm[field]]

        return dict_to_norm

    aws_policy_str_fields: Set[str] = {"Version", "Id", "Sid"}
    aws_policy_list_fields: Set[str] = {"Statement"}
    aws_statement_list_fields: Set[str] = {
        "Action",
        "NotAction",
        "Resource",
        "NotResource",
    }
    aws_statement_action_keys: Set[Literal["Action", "NotAction"]] = {
        "Action",
        "NotAction",
    }

    if not isinstance(policy, dict):
        raise TypeError(f"Malformed policy. Expected dict, got: {type(policy)}")

    for field in aws_policy_str_fields:
        verify_type(
            policy.get(field, ""),
            str,
            err_msg=f"Malformed Policy, expected {field} of type str",
        )

    policy = normalize_dict(policy, aws_policy_list_fields)  # type: ignore

    for statement in policy["Statement"]:
        verify_type(
            statement["Effect"],
            str,
            err_msg="Malformed Policy, expected statement Effect of type str",
        )

        # Normalize list fields
        statement = normalize_dict(statement, aws_statement_list_fields)  # type: ignore

        # Normalize Principal and NotPrincipal to look like this:
        # {"Statement":
        #   {"Principal":
        #     {"AWS": ["arn:aws:s3:::some_bucket"]}
        #   }
        # }
        # As per https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html,
        # The "*" and {"AWS": "*"} statements in Principal are equivalent, so we convert to the latter
        for field in ("Principal", "NotPrincipal"):
            if not statement.get(field):
                continue
            if statement[field] == "*":  # type: ignore
                statement[field] = {"AWS": ["*"]}  # type: ignore
            verify_type(
                statement.get(field, {}),
                dict,
                err_msg=f"Malformed Policy, expected {field} of type dict",
            )
            statement[field] = normalize_dict(statement[field])  # type: ignore

        # Normalize Condition to look like this:
        # {
        #   Statement: {
        #     Condition: {
        #       ConditionOperator: {
        #           ConditionKey: [ConditionValue]
        #       }
        #     }
        #   }
        # }
        verify_type(
            statement.get("Condition", {}),
            dict,
            err_msg="Malformed Policy, expected Condition of type dict",
        )
        for condition_operator, condition_dict in statement.get("Condition", {}).items():  # type: ignore
            for condition_key, condition_value in condition_dict.items():
                if not isinstance(condition_value, list):
                    statement["Condition"][condition_operator][condition_key] = [condition_value]  # type: ignore

        for action_key in aws_statement_action_keys:
            if action_list := statement.get(action_key):
                new_action_list = []
                for action in action_list:
                    if action.count(":") == 1:
                        service, action_name = action.split(":")
                        action = ":".join([service.lower(), action_name])
                        new_action_list.append(action)
                    else:
                        new_action_list.append(action)
                statement[action_key] = new_action_list

    return policy


def negate_condition(condition: Dict[str, Any]) -> Dict[str, Any]:
    res_condition = condition.copy()
    condition_prefix = None
    condition_key, condition_value = list(res_condition.items())[0]

    if negated := CONDITIONS_NEGATIONS.get(condition_key):
        return {negated: condition_value}

    if condition_key.count(":") == 1:
        condition_prefix, condition_key = condition_key.split(":")

    if condition_prefix == "ForAllValues":
        condition_prefix = "ForAnyValue"
    elif condition_prefix == "ForAnyValue":
        condition_prefix = "ForAllValues"
    elif condition_prefix:
        logger.warning(f"Unknown policy condition prefix: {condition_prefix}")

    if condition_key.lower().endswith("ifexists"):
        condition_key = condition_key[:-8]
        if negated := CONDITIONS_NEGATIONS.get(condition_key):
            return {f"{negated}IfExists": condition_value}

    if condition_key.lower() in ("bool", "null"):
        condition_value = {
            _condition: (
                HashableList(["true"])
                if all(str(v).lower() == "false" for v in _values)
                else HashableList(["false"])
                if all(str(v).lower() == "true" for v in _values)
                else HashableList(["true", "false"])
            )
            for _condition, _values in condition_value.items()
        }

    if condition_key == "BinaryEquals":  # there is no bloody negation
        logger.info(f"BinaryEquals used in a deny condition: {condition}")

    if condition_prefix:
        return {f"{condition_prefix}:{condition_key}": condition_value}

    return {condition_key: condition_value}


def merge_condition(
    allow_cond: Optional[Dict[str, Any]],
    deny_cond: Optional[Dict[str, Any]],
    negate: Optional[bool] = True,
    hashable: Optional[bool] = True,
) -> Optional[Dict[str, Any]]:
    res = None

    if allow_cond and not deny_cond:
        res = allow_cond

    elif negate:
        if allow_cond and deny_cond:
            res = deep_update(allow_cond, negate_condition(deny_cond))
        elif deny_cond:
            res = negate_condition(deny_cond)

    else:
        if allow_cond and deny_cond:
            res = deep_update(allow_cond, deny_cond)
        else:
            res = deny_cond

    return HashableDict.recursively(res) if hashable else res


def get_default_policy_for_managed_policy(
    managed_policy_obj: Dict[str, Any]
) -> AwsPolicyType:
    for policy in managed_policy_obj.get("PolicyVersionList", []):
        if policy.get("IsDefaultVersion", False):
            return normalize_policy(policy["Document"])
    raise ValueError(
        f"No default policy found for managed policy {managed_policy_obj['Arn']}"
    )


def deep_update(
    mapping: Dict[KeyType, Any], *updating_mappings: Dict[KeyType, Any]
) -> Dict[KeyType, Any]:
    updated_mapping = mapping.copy()
    for updating_mapping in updating_mappings:
        for k, v in updating_mapping.items():
            if k in updated_mapping:
                if isinstance(updated_mapping[k], dict) and isinstance(v, dict):
                    updated_mapping[k] = deep_update(updated_mapping[k], v)
                elif isinstance(updated_mapping[k], list) and isinstance(v, list):
                    updated_mapping[k] = list(set(updated_mapping[k] + v))
            else:
                updated_mapping[k] = v
    return updated_mapping


def wildcard_match(s: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    if "*" in pattern:
        return fnmatch(s, pattern)
    return s == pattern
