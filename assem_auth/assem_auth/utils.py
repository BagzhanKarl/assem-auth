import secrets
import time
from typing import Dict, Any, Optional

import jwt
from fastapi import Request


def generate_csrf_token() -> str:
    """
    Generate a secure random CSRF token.

    Returns:
        Randomly generated CSRF token
    """
    return secrets.token_hex(16)


def extract_token_from_header(request: Request) -> Optional[str]:
    """
    Extract JWT token from Authorization header.

    Args:
        request: FastAPI Request object

    Returns:
        JWT token or None if not found
    """
    authorization = request.headers.get("Authorization")
    if authorization and authorization.startswith("Bearer "):
        return authorization.replace("Bearer ", "")
    return None


def decode_token_without_verification(token: str, algorithms: list = None) -> Dict[str, Any]:
    """
    Decode JWT token without verifying signature - useful for debugging or analyzing token structure.
    Warning: This should not be used for authentication purposes.

    Args:
        token: JWT token string
        algorithms: List of allowed algorithms

    Returns:
        Decoded token payload
    """
    if algorithms is None:
        algorithms = ["HS256"]
    return jwt.decode(token, options={"verify_signature": False}, algorithms=algorithms)


def is_token_expired(payload: Dict[str, Any]) -> bool:
    """
    Check if a token payload is expired.

    Args:
        payload: Decoded token payload

    Returns:
        True if token is expired, False otherwise
    """
    exp = payload.get("exp")
    if not exp:
        return False
    return time.time() > exp