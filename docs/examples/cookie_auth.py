"""
Cookie-based authentication example with CSRF protection.

This example shows how to implement secure cookie-based authentication
with automatic CSRF protection using the double-submit cookie pattern.
"""

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from fastapi_jwt_harmony import (
    JWTHarmony,
    JWTHarmonyConfig,
    JWTHarmonyDep,
    JWTHarmonyException,
    JWTHarmonyOptional,
)

app = FastAPI(title='JWT Harmony Cookie Auth Example')


# User model
class User(BaseModel):
    id: str
    username: str
    email: str


class LoginRequest(BaseModel):
    username: str
    password: str


# Mock user database
USERS_DB = {'alice': {'id': '1', 'username': 'alice', 'email': 'alice@example.com', 'password': 'password123'}}  # pragma: allowlist secret

# Configure JWT for cookie-based auth with CSRF protection
JWTHarmony.configure(
    User,
    JWTHarmonyConfig(
        authjwt_secret_key='your-super-secret-key-change-in-production',  # pragma: allowlist secret
        authjwt_token_location=frozenset({'cookies'}),  # Store tokens in cookies
        authjwt_cookie_csrf_protect=True,  # Enable CSRF protection
        authjwt_cookie_secure=False,  # Set to True in production with HTTPS
        authjwt_cookie_samesite='strict',  # CSRF protection
        authjwt_access_token_expires=15 * 60,  # 15 minutes
        authjwt_refresh_token_expires=30 * 24 * 60 * 60,  # 30 days
    ),
)


# Exception handler for JWT errors
@app.exception_handler(JWTHarmonyException)
def authjwt_exception_handler(request: Request, exc: JWTHarmonyException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})


def authenticate_user(username: str, password: str) -> User | None:
    """Authenticate user with username and password."""
    user_data = USERS_DB.get(username)
    if user_data and user_data['password'] == password:
        return User(**{k: v for k, v in user_data.items() if k != 'password'})
    return None


@app.post('/auth/login')
def login(credentials: LoginRequest, response: Response, Authorize: JWTHarmony[User] = Depends()) -> dict[str, Any]:
    """Login endpoint that sets secure cookies."""
    user = authenticate_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid credentials')

    # Create tokens
    access_token = Authorize.create_access_token(user_claims=user, fresh=True)
    refresh_token = Authorize.create_refresh_token(user_claims=user)

    # Set secure cookies (automatically includes CSRF tokens)
    Authorize.set_access_cookies(access_token, response)
    Authorize.set_refresh_cookies(refresh_token, response)

    return {'message': 'Successfully logged in', 'user': user}


@app.post('/auth/logout')
def logout(response: Response, Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)) -> dict[str, str]:
    """Logout endpoint that clears all cookies."""
    Authorize.unset_jwt_cookies(response)
    return {'message': 'Successfully logged out'}


@app.get('/auth/me')
def get_current_user(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)) -> dict[str, Any]:
    """Get current user from cookie-based authentication."""
    return {'user': Authorize.user_claims, 'authenticated': True}


@app.get('/public')
def public_endpoint(Authorize: JWTHarmony[User] = Depends(JWTHarmonyOptional)) -> dict[str, Any]:
    """Public endpoint that works with or without authentication."""
    if Authorize.user_claims:
        return {'message': f'Hello {Authorize.user_claims.username}!', 'authenticated': True}
    else:
        return {'message': 'Hello anonymous user!', 'authenticated': False}


@app.get('/protected')
def protected_endpoint(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)) -> dict[str, Any]:
    """Protected endpoint requiring authentication."""
    user = Authorize.user_claims
    assert user is not None  # JWTHarmonyDep guarantees user is not None
    return {'message': f'Welcome {user.username}!', 'data': 'This is protected data', 'user': user}


@app.post('/protected-action')
def protected_action(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)) -> dict[str, Any]:
    """
    Protected POST endpoint that requires CSRF token.

    The CSRF token must be included in the X-CSRF-Token header.
    You can get the CSRF token from the cookie after login.
    """
    user = Authorize.user_claims
    assert user is not None  # JWTHarmonyDep guarantees user is not None
    return {'message': f'Action performed by {user.username}', 'success': True}


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8000)  # nosec


# Example usage with curl:
# 1. Start the server:
#    python cookie_auth.py
#
# 2. Login (this sets cookies):
#    curl -c cookies.txt -X POST "http://localhost:8000/auth/login" \
#      -H "Content-Type: application/json" \
#      -d '{"username": "alice", "password": "password123"}'  # pragma: allowlist secret
#
# 3. Access protected endpoint (uses cookies automatically):
#    curl -b cookies.txt "http://localhost:8000/protected"
#
# 4. For POST requests, you need the CSRF token:
#    # Get CSRF token from cookies
#    CSRF_TOKEN=$(grep csrf_access_token cookies.txt | cut -f7)
#
#    # Use it in the header
#    curl -b cookies.txt -X POST "http://localhost:8000/protected-action" \
#      -H "X-CSRF-Token: $CSRF_TOKEN"
#
# 5. Logout (clears cookies):
#    curl -b cookies.txt -c cookies.txt -X POST "http://localhost:8000/auth/logout"

# Example with JavaScript/browser:
# // Login
# const response = await fetch('/auth/login', {
#   method: 'POST',
#   headers: { 'Content-Type': 'application/json' },
#   body: JSON.stringify({ username: 'alice', password: 'password123' }),
#   credentials: 'include'  // Important: include cookies
# });
#
# // Access protected endpoint (cookies sent automatically)
# const userResponse = await fetch('/auth/me', {
#   credentials: 'include'
# });
#
# // For POST requests, get CSRF token from cookie
# function getCSRFToken() {
#   const match = document.cookie.match(/csrf_access_token=([^;]+)/);
#   return match ? match[1] : null;
# }
#
# // Protected POST action
# const actionResponse = await fetch('/protected-action', {
#   method: 'POST',
#   headers: {
#     'X-CSRF-Token': getCSRFToken()
#   },
#   credentials: 'include'
# });
