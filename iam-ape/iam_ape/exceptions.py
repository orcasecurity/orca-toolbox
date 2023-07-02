from typing import Any


class IamApeException(Exception):
    """Base class for all exceptions raised by iam_ape"""

    pass


class PolicyNotFoundException(IamApeException):
    """Raised when a policy is not found in the authorization details resport"""

    pass


class EntityNotFoundException(IamApeException):
    """Raised when an entity is not found in the authorization details resport"""

    def __init__(self, arn: str) -> None:
        super().__init__(f"Entity not found in authorization details: {arn}")


class MalformedPolicyDocumentException(IamApeException):
    """Raised when a policy document is malformed"""

    def __init__(self, expected: Any, actual: str) -> None:
        super().__init__(
            f"Malformed policy document, expected {expected}, got {actual}"
        )


class InvalidArnException(IamApeException):
    """Raised when an ARN is invalid"""

    def __init__(self, expected: str, actual: str) -> None:
        super().__init__(f"Invalid ARN, expected {expected}, got {actual}")


class AwsAuthorizationException(IamApeException):
    """Raised when an AWS authorization error occurs"""

    pass


class UnknownServiceExepction(IamApeException):
    """Raised when an unknown service is encountered"""

    def __init__(self, service: str) -> None:
        super().__init__(f"Unknown service: {service}")
