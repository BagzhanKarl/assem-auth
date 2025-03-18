from datetime import datetime, timedelta
import os
import secrets
from typing import Optional, Dict, Tuple, Any, List, Union

import jwt
from fastapi import HTTPException, Request, Response, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel


# Authentication error response model
class AuthError(BaseModel):
    detail: str
    code: str


class ServiceMode:
    """Service modes for authentication class"""
    FULL = "full"  # Full access (token creation and verification)
    VERIFY_ONLY = "verify"  # Token verification only


class AssemAUTH:
    def __init__(
            self,
            secret_key: str = None,
            algo: str = "HS256",
            access_token_expire_minutes: int = 30,
            refresh_token_expire_days: int = 7,
            token_issuer: str = "assem-api",
            token_audience: List[str] = None,
            secure_cookies: bool = True,
            cookie_domain: str = None,
            enable_csrf_protection: bool = True,
            enable_jti: bool = True,
            service_mode: str = ServiceMode.FULL
    ):
        """
        Initialize authentication service with customizable parameters.

        Args:
            secret_key: Secret key for JWT signing (if None, generated automatically)
            algo: JWT signing algorithm
            access_token_expire_minutes: Access token lifetime in minutes
            refresh_token_expire_days: Refresh token lifetime in days
            token_issuer: Token issuer (iss claim)
            token_audience: Token audience (aud claim)
            secure_cookies: Whether to set Secure flag for cookies
            cookie_domain: Cookie domain
            enable_csrf_protection: Enable CSRF protection
            enable_jti: Enable unique identifiers for tokens
            service_mode: Service mode (FULL - create and verify tokens,
                                     VERIFY_ONLY - verify tokens only)
        """
        # If key not provided, generate a secure key (in production, always set manually)
        self.secret_key = secret_key or os.environ.get("JWT_SECRET_KEY") or secrets.token_hex(32)
        self.algo = algo
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.token_issuer = token_issuer
        self.token_audience = token_audience or ["assem-client"]
        self.secure_cookies = secure_cookies
        self.cookie_domain = cookie_domain
        self.enable_csrf_protection = enable_csrf_protection
        self.enable_jti = enable_jti

        # Set service mode
        self.service_mode = service_mode

        if self.service_mode not in [ServiceMode.FULL, ServiceMode.VERIFY_ONLY]:
            raise ValueError(
                f"Invalid service mode: {service_mode}. Valid values: {ServiceMode.FULL}, {ServiceMode.VERIFY_ONLY}")

        # Initialize HTTP bearer for Authorization header token extraction
        self.http_bearer = HTTPBearer(auto_error=False)

        # Internal revoked tokens cache (should be replaced with Redis in production)
        self._revoked_tokens = set()

    def create_jwt_token(
            self,
            data: Dict[str, Any],
            expires_delta: Optional[timedelta] = None,
            token_type: str = "access"
    ) -> str:
        """
        Generate JWT token with enhanced security.

        Args:
            data: Token payload
            expires_delta: Token lifetime
            token_type: Token type ("access" or "refresh")

        Returns:
            JWT token string

        Raises:
            PermissionError: If service is in VERIFY_ONLY mode
        """
        # Check permissions for current service mode
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "This AssemAUTH instance is in verification-only mode. Token creation is not allowed.")

        to_encode = data.copy()

        # Set token creation and expiration time
        now = datetime.utcnow()

        if token_type == "access":
            expires_delta = expires_delta or timedelta(minutes=self.access_token_expire_minutes)
        else:
            expires_delta = expires_delta or timedelta(days=self.refresh_token_expire_days)

        expire = now + expires_delta

        # Add standard JWT claims for security
        to_encode.update({
            "iat": now,  # Issued At - token creation time
            "exp": expire,  # Expiration Time
            "iss": self.token_issuer,  # Issuer
            "aud": self.token_audience,  # Audience
            "type": token_type,  # Token type (access/refresh)
        })

        # Add unique token identifier (JWT ID) for revocation capability
        if self.enable_jti:
            to_encode["jti"] = secrets.token_hex(16)

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algo)

    def create_tokens(
            self,
            user_id: Union[int, str],
            additional_data: Dict[str, Any] = None
    ) -> Tuple[str, str, str]:
        """
        Create access and refresh tokens, and csrf token if needed.

        Args:
            user_id: User identifier
            additional_data: Additional data to include in the token

        Returns:
            Tuple (access_token, refresh_token, csrf_token)

        Raises:
            PermissionError: If service is in VERIFY_ONLY mode
        """
        # Check permissions for current service mode
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "This AssemAUTH instance is in verification-only mode. Token creation is not allowed.")

        data = {"sub": str(user_id)}

        # Add additional data to token (e.g., user roles)
        if additional_data:
            data.update(additional_data)

        access_token = self.create_jwt_token(
            data=data,
            expires_delta=timedelta(minutes=self.access_token_expire_minutes),
            token_type="access"
        )

        refresh_token = self.create_jwt_token(
            data=data,
            expires_delta=timedelta(days=self.refresh_token_expire_days),
            token_type="refresh"
        )

        csrf_token = ""
        if self.enable_csrf_protection:
            csrf_token = secrets.token_hex(16)

        return access_token, refresh_token, csrf_token

    def set_tokens_in_cookies(
            self,
            response: Response,
            access_token: str,
            refresh_token: str,
            csrf_token: str = ""
    ) -> None:
        """
        Set tokens in secure cookies.

        Args:
            response: FastAPI Response object
            access_token: JWT access token
            refresh_token: JWT refresh token
            csrf_token: CSRF token (if protection enabled)

        Raises:
            PermissionError: If service is in VERIFY_ONLY mode
        """
        # Check permissions for current service mode
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "This AssemAUTH instance is in verification-only mode. Setting tokens is not allowed.")

        # Define common security parameters for cookies
        cookie_params = {
            "httponly": True,  # Not accessible to JavaScript
            "samesite": "lax",  # CSRF protection
            "secure": self.secure_cookies,  # HTTPS only
        }

        if self.cookie_domain:
            cookie_params["domain"] = self.cookie_domain

        # Set cookie expiration times
        access_expires = self.access_token_expire_minutes * 60
        refresh_expires = self.refresh_token_expire_days * 24 * 60 * 60

        # Set token cookies
        response.set_cookie(
            key="access_token",
            value=access_token,
            max_age=access_expires,
            **cookie_params
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=refresh_expires,
            **cookie_params
        )

        # If CSRF protection is enabled, set CSRF token
        # CSRF token should not be httponly, to be accessible by JavaScript
        if self.enable_csrf_protection and csrf_token:
            response.set_cookie(
                key="csrf_token",
                value=csrf_token,
                max_age=access_expires,
                httponly=False,  # Accessible to JavaScript
                samesite="lax",
                secure=self.secure_cookies
            )

            # Also send CSRF token in header for convenience
            response.headers["X-CSRF-Token"] = csrf_token

    def verify_token(
            self,
            token: str,
            token_type: str = "access"
    ) -> Dict[str, Any]:
        """
        Verify JWT token and return its contents.
        This function is available in any service mode.

        Args:
            token: JWT token to verify
            token_type: Expected token type ("access" or "refresh")

        Returns:
            Token contents

        Raises:
            HTTPException: If token is invalid or expired
        """
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=AuthError(detail="Token not provided", code="token_missing").dict()
            )

        try:
            # Decode and verify token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algo],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "require": ["exp", "iat", "iss", "aud", "sub", "type"]
                },
                issuer=self.token_issuer,
                audience=self.token_audience
            )

            # Verify token type
            if payload.get("type") != token_type:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=AuthError(detail=f"Invalid token type, expected {token_type}",
                                     code="invalid_token_type").dict()
                )

            # Check if token is revoked
            if self.enable_jti and payload.get("jti") in self._revoked_tokens:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=AuthError(detail="Token has been revoked", code="token_revoked").dict()
                )

            return payload

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=AuthError(detail="Token expired", code="token_expired").dict()
            )
        except jwt.InvalidIssuerError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=AuthError(detail="Invalid token issuer", code="invalid_issuer").dict()
            )
        except jwt.InvalidAudienceError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=AuthError(detail="Invalid token audience", code="invalid_audience").dict()
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=AuthError(detail="Invalid token", code="invalid_token").dict()
            )

    def get_token_from_request(self, request: Request) -> Tuple[str, str]:
        """
        Get token from request, checking cookies and Authorization header.
        This function is available in any service mode.

        Args:
            request: FastAPI request object

        Returns:
            Tuple (token, token source)
        """
        # Check cookies first
        token = request.cookies.get("access_token")
        source = "cookie"

        # If token not in cookie, check Authorization header
        if not token:
            auth = request.headers.get("Authorization")
            if auth and auth.startswith("Bearer "):
                token = auth.replace("Bearer ", "")
                source = "header"

        return token, source

    def get_token_payload(
            self,
            request: Request,
            verify_csrf: bool = True
    ) -> Dict[str, Any]:
        """
        Get the full token payload, including all additional data.

        Args:
            request: FastAPI Request object
            verify_csrf: Whether to verify CSRF token for non-read requests

        Returns:
            Dictionary with token contents, including user_id (sub) and all additional data

        Raises:
            HTTPException: If user is not authenticated or an error occurs
        """
        token, source = self.get_token_from_request(request)

        # Check CSRF token if protection is enabled and method is unsafe
        if (self.enable_csrf_protection and
                verify_csrf and
                source == "cookie" and
                request.method not in ["GET", "HEAD", "OPTIONS"]):

            csrf_cookie = request.cookies.get("csrf_token")
            csrf_header = request.headers.get("X-CSRF-Token")

            if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=AuthError(detail="Invalid CSRF token", code="invalid_csrf").dict()
                )

        # Verify access token and return its contents
        return self.verify_token(token, "access")

    def get_current_user(
            self,
            request: Request,
            verify_csrf: bool = True
    ) -> str:
        """
        Get the current authenticated user's ID.

        Args:
            request: FastAPI Request object
            verify_csrf: Whether to verify CSRF token for non-read requests

        Returns:
            User ID

        Raises:
            HTTPException: If user is not authenticated or an error occurs
        """
        payload = self.get_token_payload(request, verify_csrf)
        return payload["sub"]

    def get_user_data(
            self,
            request: Request,
            key: str = None,
            verify_csrf: bool = True
    ) -> Any:
        """
        Get user data from token.

        Args:
            request: FastAPI Request object
            key: Key for getting specific field from token (if None, returns entire payload)
            verify_csrf: Whether to verify CSRF token for non-read requests

        Returns:
            Value of requested field or entire token payload if key=None

        Raises:
            HTTPException: If user is not authenticated or an error occurs
            KeyError: If requested key is not present in token
        """
        payload = self.get_token_payload(request, verify_csrf)

        # If key not specified, return entire payload
        if key is None:
            return payload

        # If key specified, try to get its value
        if key in payload:
            return payload[key]

        # If key not found, return None
        return None

    def get_current_user_dependency(self, verify_csrf: bool = True):
        """
        Create FastAPI dependency for getting current user.
        This function is available in any service mode.

        Args:
            verify_csrf: Whether to verify CSRF token

        Returns:
            Callable for use as a dependency
        """

        async def _get_current_user(request: Request):
            return self.get_current_user(request, verify_csrf)

        return _get_current_user

    def get_user_data_dependency(self, key: str = None, verify_csrf: bool = True):
        """
        Create FastAPI dependency for getting user data from token.

        Args:
            key: Key for getting specific field from token (if None, returns entire payload)
            verify_csrf: Whether to verify CSRF token

        Returns:
            Callable for use as a dependency
        """

        async def _get_user_data(request: Request):
            return self.get_user_data(request, key, verify_csrf)

        return _get_user_data

    def refresh_access_token(
            self,
            request: Request,
            response: Response
    ) -> Dict[str, str]:
        """
        Refresh access_token using refresh_token.

        Args:
            request: FastAPI Request object
            response: FastAPI Response object

        Returns:
            Dictionary with success message

        Raises:
            PermissionError: If service is in VERIFY_ONLY mode
            HTTPException: If refresh_token is invalid or expired
        """
        # Check permissions for current service mode
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "This AssemAUTH instance is in verification-only mode. Token refresh is not allowed.")

        refresh_token = request.cookies.get("refresh_token")

        # Verify refresh token
        payload = self.verify_token(refresh_token, "refresh")

        # Get user data from token
        user_id = payload["sub"]

        # Save additional data from old token
        additional_data = {k: v for k, v in payload.items()
                           if k not in ["exp", "iat", "iss", "aud", "sub", "jti", "type"]}

        # Create new tokens
        access_token, new_refresh_token, csrf_token = self.create_tokens(
            user_id,
            additional_data
        )

        # Revoke old refresh token if jti support is enabled
        if self.enable_jti and "jti" in payload:
            self._revoked_tokens.add(payload["jti"])

        # Set new tokens in cookies
        self.set_tokens_in_cookies(response, access_token, new_refresh_token, csrf_token)

        return {
            "message": "Tokens refreshed successfully",
            "code": "tokens_refreshed",
            "user_id": user_id
        }

    def logout(self, request: Request, response: Response) -> Dict[str, str]:
        """
        Log out user by revoking tokens.

        Args:
            request: FastAPI Request object
            response: FastAPI Response object

        Returns:
            Dictionary with success message

        Raises:
            PermissionError: If service is in VERIFY_ONLY mode
        """
        # Check permissions for current service mode
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "This AssemAUTH instance is in verification-only mode. Logout is not allowed.")

        # Revoke tokens if jti support is enabled
        if self.enable_jti:
            # Get current tokens
            access_token = request.cookies.get("access_token")
            refresh_token = request.cookies.get("refresh_token")

            # Revoke tokens if they exist
            try:
                if access_token:
                    access_payload = jwt.decode(
                        access_token,
                        self.secret_key,
                        algorithms=[self.algo],
                        options={"verify_exp": False}  # Skip expiration check
                    )
                    if "jti" in access_payload:
                        self._revoked_tokens.add(access_payload["jti"])

                if refresh_token:
                    refresh_payload = jwt.decode(
                        refresh_token,
                        self.secret_key,
                        algorithms=[self.algo],
                        options={"verify_exp": False}  # Skip expiration check
                    )
                    if "jti" in refresh_payload:
                        self._revoked_tokens.add(refresh_payload["jti"])
            except:
                # Ignore errors when decoding tokens
                pass

        # Delete cookies
        response.delete_cookie(key="access_token", path="/", domain=self.cookie_domain)
        response.delete_cookie(key="refresh_token", path="/", domain=self.cookie_domain)

        if self.enable_csrf_protection:
            response.delete_cookie(key="csrf_token", path="/", domain=self.cookie_domain)

        return {"message": "Logout successful", "code": "logout_success"}
