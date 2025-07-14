# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of FastAPI JWT Harmony
- Type-safe JWT authentication with Pydantic integration
- FastAPI dependency injection system with multiple dependency types
- Support for both header and cookie-based authentication
- CSRF protection for cookie authentication
- WebSocket authentication support
- Token denylist/blacklist functionality
- Asymmetric algorithm support (RS256, ES256, etc.)
- Comprehensive test suite with 111+ passing tests
- Modern src-layout project structure

### Features
- **JWTHarmony** - Main HTTP authentication class
- **JWTHarmonyWS** - WebSocket authentication class
- **JWTHarmonyConfig** - Pydantic-based configuration
- **Multiple Dependencies**:
  - `JWTHarmonyDep` - Requires valid access token
  - `JWTHarmonyOptional` - Optional JWT validation
  - `JWTHarmonyRefresh` - Requires valid refresh token
  - `JWTHarmonyFresh` - Requires fresh access token
  - `JWTHarmonyBare` - No automatic validation

### Configuration
- Flexible token location support (headers, cookies, or both)
- Customizable token expiration times
- CSRF protection configuration
- Cookie security settings
- Asymmetric key support
- Token validation options

### Security
- CSRF double-submit cookie pattern
- Secure cookie attributes (HttpOnly, Secure, SameSite)
- Token revocation via denylist
- Clock skew tolerance
- Audience and issuer validation

### Developer Experience
- 100% type coverage with mypy
- Comprehensive documentation
- Modern Python 3.11+ support
- ruff and pylint code quality checks
- Extensive test coverage
- Clear error messages and exception handling

## [0.0.0] - 2024-01-XX

### Added
- Project initialization
- Core authentication framework
- Basic JWT token handling
- FastAPI integration
- Pydantic model support

---

## Migration Guide

### From fastapi-jwt-auth

If you're migrating from `fastapi-jwt-auth`, here are the key changes:

#### Class Names
```python
# Old
from fastapi_jwt_auth import AuthJWT

# New
from fastapi_jwt_harmony import JWTHarmony
```

#### Configuration
```python
# Old
@AuthJWT.load_config
def get_config():
    return Settings()

# New
JWTHarmony.configure(User, JWTHarmonyConfig(...))
```

#### Dependencies
```python
# Old
@app.get("/protected")
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    return {"user": Authorize.get_jwt_subject()}

# New
@app.get("/protected")
def protected(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    return {"user": Authorize.user_claims}  # Typed User model!
```

#### WebSocket Authentication
```python
# Old
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, Authorize: AuthJWT = Depends()):
    Authorize._websocket = websocket  # Hacky
    Authorize.jwt_required()

# New
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)
):
    Authorize.jwt_required(token)  # Clean API
```

### Breaking Changes
- Configuration is now done via `JWTHarmony.configure()` instead of decorators
- WebSocket authentication has a dedicated class `JWTHarmonyWS`
- User claims are now typed Pydantic models instead of raw dictionaries
- Dependency injection is more explicit with typed dependencies
- Project structure moved to src-layout

### Benefits of Migration
- **Type Safety**: Full mypy support with typed user claims
- **Better API**: Cleaner, more explicit dependency injection
- **Enhanced Security**: Improved CSRF protection and cookie handling
- **Modern Codebase**: Python 3.11+, latest best practices
- **Better Documentation**: Comprehensive examples and guides
