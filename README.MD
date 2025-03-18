# Assem

[![PyPI version](https://img.shields.io/pypi/v/assem.svg)](https://pypi.org/project/assem/)
[![Python versions](https://img.shields.io/pypi/pyversions/assem.svg)](https://pypi.org/project/assem/)
[![License](https://img.shields.io/github/license/BagzhanKarl/assem-auth.svg)](https://github.com/BagzhanKarl/assem-auth/blob/master/LICENSE)

A flexible and secure JWT authentication framework for FastAPI applications.

## Features

- 🔒 JWT-based authentication with refresh tokens
- 🛡️ CSRF protection
- 🍪 Secure cookie handling
- 🔄 Token refresh mechanism
- ⏲️ Configurable token expiration
- 🔍 Easy token validation and user identification
- 📦 Simple integration with FastAPI

## Installation

```bash
pip install assem
```

## Quick Start

```python
from fastapi import FastAPI, Depends, Request, Response
from assem import AssemAUTH

app = FastAPI()

# Initialize authentication with default settings
auth = AssemAUTH(secret_key="your-secret-key")

# Login endpoint
@app.post("/login")
async def login(username: str, password: str, response: Response):
    # Validate user credentials (replace with your authentication logic)
    if username == "demo" and password == "password":
        user_id = "user123"
        
        # Create tokens (access, refresh, csrf)
        access_token, refresh_token, csrf_token = auth.create_tokens(
            user_id, 
            additional_data={"role": "admin", "name": "Demo User"}
        )
        
        # Set tokens in cookies
        auth.set_tokens_in_cookies(response, access_token, refresh_token, csrf_token)
        
        return {"message": "Login successful"}
    else:
        return {"message": "Invalid credentials"}

# Protected endpoint using dependency
@app.get("/me")
async def get_current_user(user_data = Depends(auth.get_user_data_dependency())):
    return {
        "user_id": user_data["sub"],
        "role": user_data.get("role"),
        "name": user_data.get("name")
    }

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
```

## Advanced Usage

### Custom Token Configuration

```python
auth = AssemAUTH(
    secret_key="your-secret-key",
    algo="HS256",
    access_token_expire_minutes=15,
    refresh_token_expire_days=7,
    token_issuer="your-api",
    token_audience=["your-frontend"],
    secure_cookies=True,
    cookie_domain="yourdomain.com",
    enable_csrf_protection=True,
    enable_jti=True
)
```

### Verification-Only Mode

You can create an instance that only verifies tokens (useful for microservices):

```python
from assem import AssemAUTH, ServiceMode

auth_verifier = AssemAUTH(
    secret_key="your-secret-key",
    service_mode=ServiceMode.VERIFY_ONLY
)
```

### Working with User Data

The framework provides multiple ways to access user data:

```python
# Get just the user ID
@app.get("/user-id")
async def get_user_id(request: Request):
    user_id = auth.get_current_user(request)
    return {"user_id": user_id}

# Get a specific field from the token
@app.get("/user-role")
async def get_user_role(request: Request):
    role = auth.get_user_data(request, key="role")
    return {"role": role}

# Get all user data from token
@app.get("/user-all")
async def get_all_user_data(request: Request):
    all_data = auth.get_user_data(request)
    return all_data
```

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
