"""
Basic usage example for FastAPI JWT Harmony.

This example demonstrates the most common authentication patterns.
"""

from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyConfig, JWTHarmonyDep, JWTHarmonyRefresh

app = FastAPI(title='JWT Harmony Basic Example')


# Define your user model
class User(BaseModel):
    id: str
    username: str
    email: str
    role: str = 'user'


class LoginRequest(BaseModel):
    username: str
    password: str


# Mock user database
USERS_DB = {
    'john': {'id': '1', 'username': 'john', 'email': 'john@example.com', 'password': 'secret123', 'role': 'user'},  # pragma: allowlist secret
    'admin': {'id': '2', 'username': 'admin', 'email': 'admin@example.com', 'password': 'admin123', 'role': 'admin'},  # pragma: allowlist secret
}

# Configure JWT (simple way with dict)
JWTHarmony.configure(
    User,
    {
        'authjwt_secret_key': 'your-super-secret-key-change-in-production',  # pragma: allowlist secret
        'authjwt_token_location': {'headers'},  # Use headers for this example
        'authjwt_access_token_expires': 15 * 60,  # 15 minutes
        'authjwt_refresh_token_expires': 30 * 24 * 60 * 60,  # 30 days
    },
)

# Alternative: using JWTHarmonyConfig object
# from fastapi_jwt_harmony import JWTHarmonyConfig
# JWTHarmony.configure(
#     User,
#     JWTHarmonyConfig(
#         authjwt_secret_key="your-super-secret-key-change-in-production",  # pragma: allowlist secret
#         authjwt_token_location={"headers"},  # Use headers for this example
#         authjwt_access_token_expires=15 * 60,  # 15 minutes
#         authjwt_refresh_token_expires=30 * 24 * 60 * 60,  # 30 days
#     )
# )


def authenticate_user(username: str, password: str) -> User | None:
    """Authenticate user with username and password."""
    user_data = USERS_DB.get(username)
    if user_data and user_data['password'] == password:
        return User(**{k: v for k, v in user_data.items() if k != 'password'})
    return None


@app.post('/auth/login')
def login(credentials: LoginRequest, Authorize: JWTHarmony[User] = Depends()) -> dict[str, Any]:
    """Login endpoint that returns JWT tokens."""
    user = authenticate_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid credentials')

    # Create tokens with user claims
    access_token = Authorize.create_access_token(user_claims=user)
    refresh_token = Authorize.create_refresh_token(user_claims=user)

    return {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'bearer', 'user': user}


@app.post('/auth/refresh')
def refresh_token(Authorize: JWTHarmony[User] = Depends(JWTHarmonyRefresh)) -> dict[str, str]:
    """Refresh access token using refresh token."""
    current_user = Authorize.user_claims
    new_access_token = Authorize.create_access_token(user_claims=current_user)

    return {'access_token': new_access_token, 'token_type': 'bearer'}


@app.get('/auth/me')
def get_current_user(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)) -> dict[str, Any]:
    """Get current user information from JWT token."""
    return {'user': Authorize.user_claims, 'token_subject': Authorize.get_jwt_subject(), 'token_id': Authorize.get_jti()}


@app.get('/protected')
def protected_endpoint(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)) -> dict[str, Any]:
    """Protected endpoint that requires authentication."""
    user = Authorize.user_claims
    assert user is not None  # JWTHarmonyDep guarantees user is not None
    return {'message': f'Hello {user.username}!', 'user_role': user.role, 'protected_data': 'This is sensitive information'}


@app.get('/admin-only')
def admin_endpoint(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)) -> dict[str, str]:
    """Admin-only endpoint with role-based access control."""
    user = Authorize.user_claims
    assert user is not None  # JWTHarmonyDep guarantees user is not None

    if user.role != 'admin':
        raise HTTPException(status_code=403, detail='Admin access required')

    return {'message': 'Welcome admin!', 'admin_data': 'Top secret admin information'}


def main() -> None:
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8000)  # nosec


if __name__ == '__main__':
    main()


# Example usage:
# 1. Start the server:
#    python basic_usage.py
#
# 2. Login to get tokens:
#    curl -X POST "http://localhost:8000/auth/login" \
#      -H "Content-Type: application/json" \
#      -d '{"username": "john", "password": "secret123"}'  # pragma: allowlist secret
#
# 3. Use access token for protected endpoints:
#    curl -X GET "http://localhost:8000/protected" \
#      -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
#
# 4. Refresh token when needed:
#    curl -X POST "http://localhost:8000/auth/refresh" \
#      -H "Authorization: Bearer YOUR_REFRESH_TOKEN"
