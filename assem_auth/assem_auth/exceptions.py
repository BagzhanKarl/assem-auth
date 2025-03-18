from pydantic import BaseModel


class AuthError(BaseModel):
    """Authentication error response model"""
    detail: str
    code: str


class AssemAuthException(Exception):
    """Base exception for AssemAUTH"""
    pass


class TokenCreationError(AssemAuthException):
    """Exception raised when token creation fails"""
    pass


class TokenVerificationError(AssemAuthException):
    """Exception raised when token verification fails"""
    pass


class InvalidServiceModeError(AssemAuthException):
    """Exception raised when an invalid service mode is provided"""
    pass


class TokenRevocationError(AssemAuthException):
    """Exception raised when token revocation fails"""
    pass