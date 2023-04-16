from enum import Enum
from typing import Any, Dict, List, Optional, TypedDict


class FinalReportT(TypedDict):
    allowed_permissions: Dict[str, Any]
    denied_permissions: Dict[str, Any]
    ineffective_permissions: Dict[str, Any]


class AwsPolicyStatementType(TypedDict, total=False):
    Effect: str
    Sid: Optional[str]
    Action: Optional[List[str]]
    NotAction: Optional[List[str]]
    Resource: Optional[List[str]]
    NotResource: Optional[List[str]]
    Principal: Optional[Dict[str, Any]]
    NotPrincipal: Optional[Dict[str, Any]]
    Condition: Optional[Dict[str, Any]]


class AwsPolicyType(TypedDict, total=False):
    Version: Optional[str]
    Id: Optional[str]
    Statement: List[AwsPolicyStatementType]


class EntityType(Enum):
    user: str = "User"
    group: str = "Group"
    role: str = "Role"


class ActionDict(TypedDict):
    Action: str
    Resource: Optional[str]
    NotResource: Optional[str]
    Condition: Optional[Dict[str, Any]]
    Source: str


class IneffectiveActionDict(ActionDict):
    DeniedBy: str


class PermissionsContainerDict(TypedDict):
    allowed_permissions: List[ActionDict]
    denied_permissions: List[ActionDict]
    ineffective_permissions: List[ActionDict]
