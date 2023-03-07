import os
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class PolicyElement:
    WILDCARD: Literal["*"] = "*"
    EFFECT: Literal["Effect"] = "Effect"
    ALLOW: Literal["Allow"] = "Allow"
    DENY: Literal["Deny"] = "Deny"
    ACTION: Literal["Action"] = "Action"
    NOTACTION: Literal["NotAction"] = "NotAction"
    RESOURCE: Literal["Resource"] = "Resource"
    NOTRESOURCE: Literal["NotResource"] = "NotResource"
    CONDITION: Literal["Condition"] = "Condition"


CONDITIONS_NEGATIONS = {
    "StringEquals": "StringNotEquals",
    "StringNotEquals": "StringEquals",
    "StringEqualsIgnoreCase": "StringNotEqualsIgnoreCase",
    "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
    "StringLike": "StringNotLike",
    "StringNotLike": "StringLike",
    "NumericEquals": "NumericNotEquals",
    "NumericNotEquals": "NumericEquals",
    "NumericLessThan": "NumericGreaterThanEquals",
    "NumericGreaterThanEquals": "NumericLessThan",
    "NumericLessThanEquals": "NumericGreaterThan",
    "NumericGreaterThan": "NumericLessThanEquals",
    "DateEquals": "DateNotEquals",
    "DateNotEquals": "DateEquals",
    "DateLessThan": "DateGreaterThanEquals",
    "DateGreaterThanEquals": "DateLessThan",
    "DateLessThanEquals": "DateGreaterThan",
    "DateGreaterThan": "DateLessThanEquals",
    "IpAddress": "NotIpAddress",
    "NotIpAddress": "IpAddress",
    "ArnEquals": "ArnNotEquals",
    "ArnNotEquals": "ArnEquals",
    "ArnLike": "ArnNotLike",
    "ArnNotLike": "ArnLike",
}

actions_json_location = os.path.join(
    os.path.dirname(__file__),
    "aws_iam_actions",
    "aws_iam_actions.tar.gz",
)
