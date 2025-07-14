# API Reference

Complete API documentation for FastAPI JWT Harmony.

## Table of Contents

- [Configuration](#configuration)
- [Main Classes](#main-classes)
- [Dependencies](#dependencies)
- [Exceptions](#exceptions)
- [Utilities](#utilities)

## Configuration

### JWTHarmonyConfig

The main configuration class using Pydantic for validation.

```python
class JWTHarmonyConfig(BaseSettings):
    # Core settings
    authjwt_secret_key: str | None = None
    authjwt_public_key: str | None = None
    authjwt_private_key: str | None = None
    authjwt_algorithm: str = "HS256"
    authjwt_decode_algorithms: list[str] | None = None
    authjwt_decode_leeway: int = 0
    authjwt_encode_issuer: str | None = None
    authjwt_decode_issuer: str | None = None
    authjwt_decode_audience: str | list[str] | None = None

    # Token location and validation
    authjwt_token_location: frozenset[Literal["headers", "cookies"]] = frozenset({"cookies"})
    authjwt_denylist_enabled: bool = False
    authjwt_denylist_token_checks: set[str] = {"access", "refresh"}

    # Headers configuration
    authjwt_header_name: str = "Authorization"
    authjwt_header_type: str = "Bearer"

    # Token expiration
    authjwt_access_token_expires: bool | int | timedelta = 900  # 15 minutes
    authjwt_refresh_token_expires: bool | int | timedelta = 2592000  # 30 days

    # Cookies configuration
    authjwt_access_cookie_key: str = "access_token_cookie"
    authjwt_refresh_cookie_key: str = "refresh_token_cookie"
    authjwt_access_cookie_path: str = "/"
    authjwt_refresh_cookie_path: str = "/"
    authjwt_cookie_max_age: int | None = None
    authjwt_cookie_domain: str | None = None
    authjwt_cookie_secure: bool = False
    authjwt_cookie_samesite: str | None = None

    # CSRF protection
    authjwt_cookie_csrf_protect: bool = True
    authjwt_access_csrf_cookie_key: str = "csrf_access_token"
    authjwt_refresh_csrf_cookie_key: str = "csrf_refresh_token"
    authjwt_access_csrf_cookie_path: str = "/"
    authjwt_refresh_csrf_cookie_path: str = "/"
    authjwt_access_csrf_header_name: str = "X-CSRF-Token"
    authjwt_refresh_csrf_header_name: str = "X-CSRF-Token"
    authjwt_csrf_methods: set[str] = {"POST", "PUT", "DELETE", "PATCH"}
```

#### Configuration Methods

- **from_env()**: Load configuration from environment variables
- **from_file()**: Load configuration from JSON/YAML file

## Main Classes

### JWTHarmony[UserModelT]

The main HTTP authentication class for FastAPI applications.

#### Initialization

```python
def __init__(self, req: Optional[Request] = None, res: Optional[Response] = None) -> None
```

#### Class Methods

```python
@classmethod
def configure(
    cls,
    user_model_class: type[UserModelT],
    config: Optional[Union[JWTHarmonyConfig, dict[str, Any]]] = None,
    denylist_callback: Optional[Callable[[dict[str, Union[str, int, bool]]], bool]] = None
) -> None
```

Configure the JWT authentication system with either a JWTHarmonyConfig object or a dictionary.

#### Token Creation

```python
def create_access_token(
    self,
    subject: Optional[Union[str, int]] = None,
    fresh: Optional[bool] = False,
    algorithm: Optional[str] = None,
    headers: Optional[dict[str, Any]] = None,
    expires_time: Optional[Union[timedelta, int, bool]] = None,
    audience: Optional[Union[str, list[str]]] = None,
    user_claims: Optional[Union[dict[str, Any], UserModelT]] = None,
) -> str
```

Create a new access token.

```python
def create_refresh_token(
    self,
    subject: Optional[Union[str, int]] = None,
    algorithm: Optional[str] = None,
    headers: Optional[dict[str, Any]] = None,
    expires_time: Optional[Union[timedelta, int, bool]] = None,
    audience: Optional[Union[str, list[str]]] = None,
    user_claims: Optional[Union[dict[str, Any], UserModelT]] = None,
) -> str
```

Create a new refresh token.

#### Token Validation

```python
def jwt_required(self, auth_from: str = "request", token: Optional[str] = None, verify_type: bool = True) -> None
```

Verify JWT token is present and valid.

```python
def jwt_optional(self, auth_from: str = "request", token: Optional[str] = None, verify_type: bool = True) -> None
```

Optionally verify JWT token if present.

```python
def jwt_refresh_token_required(self, auth_from: str = "request", token: Optional[str] = None) -> None
```

Verify refresh token is present and valid.

```python
def fresh_jwt_required(self, auth_from: str = "request", token: Optional[str] = None) -> None
```

Verify fresh access token is present and valid.

#### Cookie Management

```python
def set_access_cookies(
    self,
    encoded_access_token: str,
    response: Optional[Response] = None,
    max_age: Optional[int] = None
) -> None
```

Set access token cookie.

```python
def set_refresh_cookies(
    self,
    encoded_refresh_token: str,
    response: Optional[Response] = None,
    max_age: Optional[int] = None
) -> None
```

Set refresh token cookie.

```python
def unset_jwt_cookies(self, response: Optional[Response] = None) -> None
```

Remove all JWT cookies.

```python
def unset_access_cookies(self, response: Optional[Response] = None) -> None
```

Remove access token cookies.

```python
def unset_refresh_cookies(self, response: Optional[Response] = None) -> None
```

Remove refresh token cookies.

#### Token Information

```python
def get_jwt_subject(self) -> Optional[str]
```

Get the subject (sub claim) from the current JWT token.

```python
def get_jti(self) -> Optional[str]
```

Get the JWT ID (jti claim) from the current token.

```python
def get_raw_jwt(self, encoded_token: Optional[str] = None) -> Optional[dict[str, Union[str, int, bool]]]
```

Get raw JWT payload.

```python
def get_unverified_jwt_headers(self, encoded_token: Optional[str] = None) -> Optional[dict[str, Any]]
```

Get JWT headers without verification.

#### Properties

```python
@property
def token(self) -> Optional[str]
```

Current JWT token.

```python
@property
def user_claims(self) -> Optional[UserModelT]
```

User claims as typed Pydantic model.

```python
@property
def config(self) -> JWTHarmonyConfig
```

Current configuration.

### JWTHarmonyWS[UserModelT]

WebSocket-specific JWT authentication class.

#### Initialization

```python
def __init__(self) -> None
```

#### WebSocket-Specific Methods

```python
def set_websocket(self, websocket: WebSocket) -> None
```

Set WebSocket connection for cookie-based auth.

```python
def set_csrf_token(self, csrf_token: str) -> None
```

Set CSRF token for cookie-based WebSocket auth.

```python
def jwt_required(self, token: Optional[str] = None) -> None
```

Verify JWT token for WebSocket connection.

```python
def jwt_optional(self, token: Optional[str] = None) -> None
```

Optionally verify JWT token for WebSocket.

```python
def jwt_refresh_token_required(self, token: Optional[str] = None) -> None
```

Verify refresh token for WebSocket.

```python
def fresh_jwt_required(self, token: Optional[str] = None) -> None
```

Verify fresh token for WebSocket.

## Dependencies

### JWTHarmonyDep

Dependency that requires a valid access token.

```python
def JWTHarmonyDep(
    req: Request = None,
    res: Response = None
) -> JWTHarmony[Any]
```

### JWTHarmonyOptional

Dependency that optionally validates JWT tokens.

```python
def JWTHarmonyOptional(
    req: Request = None,
    res: Response = None
) -> JWTHarmony[Any]
```

### JWTHarmonyRefresh

Dependency that requires a valid refresh token.

```python
def JWTHarmonyRefresh(
    req: Request = None,
    res: Response = None
) -> JWTHarmony[Any]
```

### JWTHarmonyFresh

Dependency that requires a fresh access token.

```python
def JWTHarmonyFresh(
    req: Request = None,
    res: Response = None
) -> JWTHarmony[Any]
```

### JWTHarmonyBare

Dependency with no automatic token validation.

```python
def JWTHarmonyBare(
    req: Request = None,
    res: Response = None
) -> JWTHarmony[Any]
```

### JWTHarmonyWebSocket

WebSocket dependency for JWT authentication.

```python
def JWTHarmonyWebSocket() -> JWTHarmonyWS[Any]
```

## Exceptions

### JWTHarmonyException

Base exception class for all JWT Harmony errors.

```python
class JWTHarmonyException(Exception):
    def __init__(self, status_code: int, message: str)
```

### Specific Exceptions

- **MissingTokenError**: Token is missing from request
- **JWTDecodeError**: Token is invalid or malformed
- **InvalidHeaderError**: Authorization header is malformed
- **TokenExpired**: Token has expired
- **FreshTokenRequired**: Fresh token is required
- **AccessTokenRequired**: Access token is required
- **RefreshTokenRequired**: Refresh token is required
- **RevokedTokenError**: Token has been revoked
- **CSRFError**: CSRF token is missing or invalid

All exceptions inherit from `JWTHarmonyException` and include:
- `status_code`: HTTP status code
- `message`: Error description

## Utilities

### get_jwt_identifier()

```python
def get_jwt_identifier() -> str
```

Generate a unique JWT identifier (jti).

## Type Definitions

### UserModelT

Type variable representing a Pydantic BaseModel for user data.

```python
UserModelT = TypeVar('UserModelT', bound=BaseModel)
```

### TokenLocation

Literal type for token location options.

```python
TokenLocation = Literal["headers", "cookies"]
```

## Example Usage

### Basic Setup

```python
from fastapi import FastAPI, Depends
from pydantic import BaseModel
from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyDep

app = FastAPI()

class User(BaseModel):
    id: str
    username: str

# Simple configuration with dictionary
JWTHarmony.configure(User, {"authjwt_secret_key": "secret"})  # pragma: allowlist secret

# Or with JWTHarmonyConfig object for advanced usage
# from fastapi_jwt_harmony import JWTHarmonyConfig
# JWTHarmony.configure(User, JWTHarmonyConfig(authjwt_secret_key="secret"))  # pragma: allowlist secret

@app.get("/protected")
def protected(auth: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    return {"user": auth.user_claims}
```

### Advanced Configuration

```python
from datetime import timedelta

# With dictionary (simple)
config_dict = {
    "authjwt_secret_key": "your-secret-key",  # pragma: allowlist secret
    "authjwt_token_location": {"headers", "cookies"},
    "authjwt_access_token_expires": timedelta(minutes=15),
    "authjwt_refresh_token_expires": timedelta(days=30),
    "authjwt_cookie_csrf_protect": True,
    "authjwt_cookie_secure": True,
    "authjwt_cookie_samesite": "strict",
}

JWTHarmony.configure(User, config_dict)

# Or with JWTHarmonyConfig object (advanced)
# from fastapi_jwt_harmony import JWTHarmonyConfig
# config = JWTHarmonyConfig(
#     authjwt_secret_key="your-secret-key",  # pragma: allowlist secret
#     authjwt_token_location={"headers", "cookies"},
#     authjwt_access_token_expires=timedelta(minutes=15),
#     authjwt_refresh_token_expires=timedelta(days=30),
#     authjwt_cookie_csrf_protect=True,
#     authjwt_cookie_secure=True,
#     authjwt_cookie_samesite="strict",
# )
# JWTHarmony.configure(User, config)
```

### With Denylist

```python
denylist = set()

def check_if_token_revoked(jwt_payload: dict) -> bool:
    return jwt_payload["jti"] in denylist

JWTHarmony.configure(
    User,
    {
        "authjwt_secret_key": "secret",  # pragma: allowlist secret
        "authjwt_denylist_enabled": True,
    },
    denylist_callback=check_if_token_revoked
)
```
