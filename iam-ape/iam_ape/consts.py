import os
import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, Literal

RESOURCE_ARN_RE = re.compile("arn:(?P<partition>[^:]*)(?::(?P<service>[^:]*))?")
# aws, aws-cn, aws-us-gov, aws-iso, aws-iso-b, aws-iso-e, aws-iso-f, aws-eusc
AWS_PARTITION_RE = re.compile("aws(-[a-z]+)*")

# ARN services an action's service is authorized on besides its own, per the AWS Service Authorization Reference
CROSS_SERVICE_RESOURCES: Dict[str, FrozenSet[str]] = {
    "ec2-instance-connect": frozenset({"ec2"}),
    "rds-data": frozenset({"rds"}),
    "redshift-data": frozenset({"redshift", "redshift-serverless"}),
    "ssm": frozenset({"ec2", "ecs"}),
    "ssmmessages": frozenset({"ssm"}),
    "sts": frozenset({"iam"}),
}


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
