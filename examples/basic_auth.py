"""
Basic example of using AssemAUTH with FastAPI.

To run this example:
1. Install dependencies: pip install fastapi uvicorn
2. Run the server: uvicorn basic_auth:app --reload
3. Visit http://localhost:8000/docs to interact with the API
"""

from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

import sys
import os

# Add the parent directory to sys.path to import assem
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from assem import AssemAUTH

# Create FastAPI app
app = FastAPI(title="AssemAUTH Example")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize AssemAUTH
auth = AssemAUTH(
    secret_key="your-super-secret-key-change-this-in-production",
    access_token_expire_minutes=15,
    refresh_token_expire_days=7,
)

# Mock user database
users_db = {
    "user1": {
        "username": "user1",
        "password": "password1",  # In production, store hashed passwords!
        "full_name": "User One",
        "email": "user1@example.com",
        "role": "user"
    },
    "admin": {
        "username": "admin",
        "password": "adminpass",  # In production, store hashed passwords!
        "full_name": "Admin User",
        "email": "admin@example.com",
        "role": "admin"
    }
}


# Login endpoint
@app.post("/login")
async def login(
        form_data: OAuth2PasswordRequestForm = Depends(),
        response: Response = Depends()
):
    user = users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    # Create tokens with additional user data
    access_token, refresh_token, csrf_token = auth.create_tokens(
        user_id=user["username"],
        additional_data={
            "role": user["role"],
            "email": user["email"],
            "full_name": user["full_name"]
        }
    )

    # Set tokens in cookies
    auth.set_tokens_in_cookies(response, access_token, refresh_token, csrf_token)

    return {
        "message": "Login successful",
        "username": user["username"],
        "csrf_token": csrf_token  # Frontend will need this for non-GET requests
    }


# Get current user info
@app.get("/me")
async def get_current_user(user_data=Depends(auth.get_user_data_dependency())):
    return {
        "username": user_data["sub"],
        "email": user_data.get("email"),
        "full_name": user_data.get("full_name"),
        "role": user_data.get("role")
    }


# Admin-only endpoint
@app.get("/admin")
async def admin_only(request: Request):
    # Get user data and check role
    user_data = auth.get_user_data(request)
    if user_data.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: Admin access required")

    return {"message": "Welcome, admin!"}


# Refresh token endpoint
@app.post("/refresh")
async def refresh_token(request: Request, response: Response):
    result = auth.refresh_access_token(request, response)
    return result


# Logout endpoint
@app.post("/logout")
async def logout(request: Request, response: Response):
    result = auth.logout(request, response)
    return result


# Public endpoint that doesn't require authentication
@app.get("/public")
async def public_endpoint():
    return {"message": "This is a public endpoint"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)