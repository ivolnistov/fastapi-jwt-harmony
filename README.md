# FastAPI JWT Harmony 🎵

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.68+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Quality](https://img.shields.io/badge/code%20quality-A+-green.svg)](https://github.com/astral-sh/ruff)

A modern, type-safe JWT authentication library for FastAPI with **Pydantic integration** - bringing harmony to your auth flow! =�

## ( Key Features

- = **Type-safe JWT authentication** with full Pydantic model support
- =� **FastAPI dependency injection** - automatic JWT validation
- <j **Multiple token locations** - headers, cookies, or both
- =� **CSRF protection** for cookie-based authentication
- = **WebSocket support** with dedicated authentication methods
- =� **User claims as Pydantic models** - strongly typed user data
- =� **Token denylist/blacklist** support for logout functionality
- � **Asymmetric algorithms** support (RS256, ES256, etc.)
- >� **100% test coverage** with comprehensive test suite

## =� Quick Start

### Installation

```bash
pip install fastapi-jwt-harmony
```

For asymmetric algorithm support:
```bash
pip install fastapi-jwt-harmony[asymmetric]
```

### Basic Example

```python
from fastapi import FastAPI, Depends
from pydantic import BaseModel
from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyDep

app = FastAPI()

# Define your user model
class User(BaseModel):
    id: str
    username: str
    email: str

# Configure JWT (simple way with dict)
JWTHarmony.configure(
    User,
    {
        "authjwt_secret_key": "your-secret-key",  # pragma: allowlist secret
        "authjwt_token_location": {"headers", "cookies"}  # Support both
    }
)

# Or use JWTHarmonyConfig for advanced configuration
# from fastapi_jwt_harmony import JWTHarmonyConfig
# JWTHarmony.configure(
#     User,
#     JWTHarmonyConfig(
#         authjwt_secret_key="your-secret-key",  # pragma: allowlist secret
#         authjwt_token_location={"headers", "cookies"}
#     )
# )

@app.post("/login")
def login(Authorize: JWTHarmony[User] = Depends()):
    # Authenticate user (your logic here)
    user = User(id="123", username="john", email="john@example.com")

    # Create tokens
    access_token = Authorize.create_access_token(user_claims=user)
    refresh_token = Authorize.create_refresh_token(user_claims=user)

    # Set cookies (optional)
    Authorize.set_access_cookies(access_token)
    Authorize.set_refresh_cookies(refresh_token)

    return {"access_token": access_token}

@app.get("/protected")
def protected_route(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    # JWT automatically validated by JWTHarmonyDep
    current_user = Authorize.user_claims  # Typed User model!
    return {"user": current_user, "message": f"Hello {current_user.username}!"}
```

## =� Dependencies Overview

FastAPI JWT Harmony provides several dependency types for different authentication needs:

```python
from fastapi_jwt_harmony import (
    JWTHarmonyDep,      # Requires valid access token
    JWTHarmonyOptional, # Optional JWT validation
    JWTHarmonyRefresh,  # Requires valid refresh token
    JWTHarmonyFresh,    # Requires fresh access token
    JWTHarmonyBare,     # No automatic validation
)

@app.get("/public")
def public_endpoint(Authorize: JWTHarmony[User] = Depends(JWTHarmonyOptional)):
    if Authorize.user_claims:
        return {"message": f"Hello {Authorize.user_claims.username}!"}
    return {"message": "Hello anonymous user!"}

@app.post("/sensitive-action")
def sensitive_action(Authorize: JWTHarmony[User] = Depends(JWTHarmonyFresh)):
    # Requires fresh token (just logged in)
    return {"message": "Sensitive action performed"}
```

## <j Cookie Authentication

Enable secure cookie-based authentication with CSRF protection:

```python
from fastapi import Response

JWTHarmony.configure(
    User,
    {
        "authjwt_secret_key": "your-secret-key",  # pragma: allowlist secret
        "authjwt_token_location": {"cookies"},
        "authjwt_cookie_csrf_protect": True,
        "authjwt_cookie_secure": True,  # HTTPS only
        "authjwt_cookie_samesite": "strict"
    }
)

@app.post("/login")
def login(response: Response, Authorize: JWTHarmony[User] = Depends()):
    user = User(id="123", username="john", email="john@example.com")
    access_token = Authorize.create_access_token(user_claims=user)

    # Set secure cookies
    Authorize.set_access_cookies(access_token, response)
    return {"message": "Logged in successfully"}

@app.post("/logout")
def logout(response: Response, Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    Authorize.unset_jwt_cookies(response)
    return {"message": "Logged out successfully"}
```

## = WebSocket Authentication

Authenticate WebSocket connections with dedicated methods:

```python
from fastapi import WebSocket, Query
from fastapi_jwt_harmony import JWTHarmonyWS, JWTHarmonyWebSocket

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)
):
    await websocket.accept()
    try:
        # Validate JWT token
        Authorize.jwt_required(token)
        user = Authorize.user_claims

        await websocket.send_text(f"Hello {user.username}!")
    except Exception as e:
        await websocket.send_text(f"Authentication failed: {str(e)}")
        await websocket.close()
```

## =� Token Denylist (Logout)

Implement secure logout with token blacklisting:

```python
# In-memory denylist (use Redis in production)
denylist = set()

def check_if_token_revoked(jwt_payload: dict) -> bool:
    jti = jwt_payload.get("jti")
    return jti in denylist

# Configure with denylist callback
JWTHarmony.configure(
    User,
    {
        "authjwt_secret_key": "your-secret-key",  # pragma: allowlist secret
        "authjwt_denylist_enabled": True,
        "authjwt_denylist_token_checks": {"access", "refresh"}
    },
    denylist_callback=check_if_token_revoked
)

@app.post("/logout")
def logout(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    jti = Authorize.get_jti()
    denylist.add(jti)  # Add to denylist
    return {"message": "Successfully logged out"}
```

## � Configuration Options

Comprehensive configuration with sensible defaults:

```python
from datetime import timedelta

JWTHarmonyConfig(
    # Core settings
    authjwt_secret_key="your-secret-key",           # Required for HS256  # pragma: allowlist secret
    authjwt_algorithm="HS256",                      # JWT algorithm
    authjwt_token_location={"headers"},             # Where to look for tokens

    # Token expiration
    authjwt_access_token_expires=timedelta(minutes=15),
    authjwt_refresh_token_expires=timedelta(days=30),

    # Headers
    authjwt_header_name="Authorization",
    authjwt_header_type="Bearer",

    # Cookies
    authjwt_cookie_secure=False,                    # Set True for HTTPS
    authjwt_cookie_csrf_protect=True,               # CSRF protection
    authjwt_cookie_samesite="strict",

    # Asymmetric keys (for RS256, ES256, etc.)
    authjwt_private_key=None,                       # For signing
    authjwt_public_key=None,                        # For verification

    # Denylist
    authjwt_denylist_enabled=False,
    authjwt_denylist_token_checks={"access", "refresh"},

    # Validation
    authjwt_decode_leeway=0,                        # Clock skew tolerance
    authjwt_decode_audience=None,                   # Expected audience
    authjwt_decode_issuer=None,                     # Expected issuer
)
```

## = Asymmetric Algorithms

Support for RS256, ES256, and other asymmetric algorithms:

```python
# Generate keys (example)
private_key = """-----BEGIN PRIVATE KEY-----  # pragma: allowlist secret
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7...
-----END PRIVATE KEY-----"""  # pragma: allowlist secret

public_key = """-----BEGIN PUBLIC KEY-----  # pragma: allowlist secret
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu7...
-----END PUBLIC KEY-----"""  # pragma: allowlist secret

JWTHarmony.configure(
    User,
    JWTHarmonyConfig(
        authjwt_algorithm="RS256",
        authjwt_private_key=private_key,  # For signing tokens  # pragma: allowlist secret
        authjwt_public_key=public_key,    # For verifying tokens  # pragma: allowlist secret
    )
)
```

## >� Testing

Run the comprehensive test suite:

```bash
# Install development dependencies
uv sync --dev

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=fastapi_jwt_harmony
```

## =� Development

```bash
# Clone the repository
git clone https://github.com/your-org/fastapi-jwt-harmony.git
cd fastapi-jwt-harmony

# Install with development dependencies
uv sync --dev

# Run tests
uv run pytest

# Run linting
uv run ruff check src/
uv run mypy src/fastapi_jwt_harmony
uv run pylint src/fastapi_jwt_harmony
```

## =� Project Status

-  **111 tests passing** - Comprehensive test coverage
-  **Type-safe** - Full mypy compatibility
-  **Modern Python** - Supports Python 3.11+
-  **Production ready** - Used in production applications

## > Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## =� License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## =O Acknowledgments

- **FastAPI** for the amazing web framework
- **Pydantic** for data validation and settings management
- **PyJWT** for JWT implementation
- **Original fastapi-jwt-auth** for inspiration

## =� Roadmap

- [ ] Rate limiting integration
- [ ] OAuth2 provider support
- [ ] Enhanced logging and monitoring
- [ ] Performance optimizations
- [ ] Documentation website

---

**Made with d for the FastAPI community**
