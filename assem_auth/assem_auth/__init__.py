"""
Assem - JWT Authentication Framework for FastAPI
===============================================

A flexible and secure authentication framework for FastAPI applications that provides
JWT-based authentication with features like token refresh, CSRF protection, and more.

Examples:
    Basic usage::

        from fastapi import FastAPI, Depends, Request, Response
        from assem import AssemAUTH

        app = FastAPI()
        auth = AssemAUTH(secret_key="your-secret-key")

        @app.post("/login")
        def login(username: str, password: str, response: Response):
            # Validate credentials
            user_id = "user123"  # User ID from database

            # Create tokens
            access_token, refresh_token, csrf_token = auth.create_tokens(user_id)

            # Set tokens in cookies
            auth.set_tokens_in_cookies(response, access_token, refresh_token, csrf_token)

            return {"message": "Login successful"}

        @app.get("/protected")
        def protected_route(user_id: str = Depends(auth.get_current_user_dependency())):
            return {"message": f"Hello, {user_id}"}
"""

__version__ = "0.1.0"

from .auth import AssemAUTH
from .exceptions import AuthError, AssemAuthException
from .service_mode import ServiceMode

__all__ = ["AssemAUTH", "AuthError", "AssemAuthException", "ServiceMode"]