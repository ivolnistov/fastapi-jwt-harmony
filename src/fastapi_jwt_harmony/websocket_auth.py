"""WebSocket JWT authentication implementation."""

import hmac
from typing import Literal, Optional

from fastapi import WebSocket

from .base import JWTHarmonyBase, UserModelT
from .exceptions import AccessTokenRequired, CSRFError, JWTDecodeError, JWTHarmonyException, MissingTokenError, RevokedTokenError


class JWTHarmonyWS(JWTHarmonyBase[UserModelT]):
    """
    WebSocket-specific JWT authentication implementation.

    This class handles JWT authentication for WebSocket connections,
    where tokens are typically passed as query parameters and CSRF
    tokens need special handling.
    """

    def __init__(self, websocket: Optional[WebSocket] = None) -> None:
        """
        Initialize WebSocket JWT handler.

        Args:
            websocket: The WebSocket connection instance
        """
        super().__init__()
        self._websocket = websocket
        self._csrf_token: Optional[str] = None

    def set_websocket(self, websocket: WebSocket) -> None:
        """
        Set the WebSocket instance.

        Args:
            websocket: The WebSocket connection
        """
        self._websocket = websocket

    def set_csrf_token(self, csrf_token: Optional[str]) -> None:
        """
        Set the CSRF token for cookie-based authentication.

        Args:
            csrf_token: The CSRF token from query parameters
        """
        self._csrf_token = csrf_token

    def jwt_required(self, token: Optional[str] = None) -> None:
        """
        Verify that a valid access token is present.

        For WebSocket, tokens can be provided directly or extracted from cookies.

        Args:
            token: Optional token string (for non-cookie auth)

        Raises:
            MissingTokenError: If no token is found
            Various JWT exceptions on validation failure
        """
        if self.jwt_in_cookies and self._websocket:
            # Handle cookie-based authentication
            self._verify_jwt_in_cookies('access')
        else:
            # Handle token-based authentication
            if token:
                self._token = token
            if not self._token:
                raise MissingTokenError('Missing access token from Query or Path')
            self._verify_jwt_in_request(self._token, 'access', 'websocket')

    def jwt_optional(self, token: Optional[str] = None) -> None:
        """
        Optionally verify JWT token if present.

        Args:
            token: Optional token string
        """
        if self.jwt_in_cookies and self._websocket:
            # Handle cookie-based authentication
            self._verify_jwt_optional_in_cookies()
        else:
            # Handle token-based authentication
            if token:
                self._token = token
                try:
                    self._verify_jwt_in_request(self._token, 'access', 'websocket')
                except JWTHarmonyException:
                    # For optional, we don't raise exceptions
                    self._token = None

    def jwt_refresh_token_required(self, token: Optional[str] = None) -> None:
        """
        Verify that a valid refresh token is present.

        Args:
            token: Optional token string (for non-cookie auth)

        Raises:
            MissingTokenError: If no token is found
            Various JWT exceptions on validation failure
        """
        if self.jwt_in_cookies and self._websocket:
            # Handle cookie-based authentication
            self._verify_jwt_in_cookies('refresh')
        else:
            # Handle token-based authentication
            if token:
                self._token = token
            if not self._token:
                raise MissingTokenError('Missing refresh token from Query or Path')
            self._verify_jwt_in_request(self._token, 'refresh', 'websocket')

    def fresh_jwt_required(self, token: Optional[str] = None) -> None:
        """
        Verify that a valid fresh access token is present.

        Args:
            token: Optional token string (for non-cookie auth)

        Raises:
            MissingTokenError: If no token is found
            FreshTokenRequired: If token is not fresh
            Various JWT exceptions on validation failure
        """
        if self.jwt_in_cookies and self._websocket:
            # Handle cookie-based authentication
            self._verify_jwt_in_cookies('access', fresh=True)
        else:
            # Handle token-based authentication
            if token:
                self._token = token
            if not self._token:
                raise MissingTokenError('Missing access token from Query or Path')
            self._verify_jwt_in_request(self._token, 'access', 'websocket', fresh=True)

    def _verify_jwt_in_cookies(self, type_token: Literal['access', 'refresh'], fresh: bool = False) -> None:
        """
        Verify JWT token from WebSocket cookies.

        Args:
            type_token: Type of token to verify
            fresh: Whether to require a fresh token
        """
        if not self._websocket:
            raise RuntimeError('WebSocket instance is required for cookie authentication')

        # Determine cookie key
        if type_token == 'access':
            cookie_key = self.config.authjwt_access_cookie_key
        else:
            cookie_key = self.config.authjwt_refresh_cookie_key

        # Extract token from cookies
        cookie = self._websocket.cookies.get(cookie_key)
        if not cookie:
            raise MissingTokenError(f'Missing cookie {cookie_key}')

        # Check CSRF protection
        if self.config.authjwt_cookie_csrf_protect:
            if not self._csrf_token:
                raise CSRFError('Missing CSRF Token')

            # Store token and verify it
            self._token = cookie
            self._verify_jwt_in_request(self._token, type_token, 'cookies', fresh)

            # Verify CSRF token matches
            decoded_token = self.get_raw_jwt()
            if decoded_token:
                csrf_in_token = decoded_token.get('csrf')
                if not csrf_in_token:
                    raise JWTDecodeError('Missing claim: csrf')
                if not hmac.compare_digest(str(csrf_in_token), str(self._csrf_token)):
                    raise CSRFError('CSRF double submit tokens do not match')
        else:
            # No CSRF protection, just verify token
            self._token = cookie
            self._verify_jwt_in_request(self._token, type_token, 'cookies', fresh)

    def _verify_jwt_optional_in_cookies(self) -> None:
        """
        Optionally verify JWT token from WebSocket cookies.

        Does not raise exceptions if token is missing or invalid.
        """
        if not self._websocket:
            return

        # Try to get access token from cookies
        cookie_key = self.config.authjwt_access_cookie_key or 'access_token_cookie'
        cookie = self._websocket.cookies.get(cookie_key)

        if not cookie:
            # No token, but that's OK for optional
            return

        try:
            # Check CSRF if enabled
            if self.config.authjwt_cookie_csrf_protect:
                if not self._csrf_token:
                    # No CSRF token provided but required - treat as no auth for optional
                    return

                self._token = cookie
                self._verify_jwt_in_request(self._token, 'access', 'cookies')

                # Verify CSRF
                decoded_token = self.get_raw_jwt()
                if decoded_token:
                    csrf_in_token = decoded_token.get('csrf')
                    if not csrf_in_token:
                        # No CSRF in token, treat as no auth
                        self._token = None
                        return

                    if not hmac.compare_digest(str(csrf_in_token), str(self._csrf_token)):
                        # CSRF mismatch, treat as no auth
                        self._token = None
                        return
            else:
                # No CSRF protection
                self._token = cookie
                self._verify_jwt_in_request(self._token, 'access', 'cookies')
        except (RevokedTokenError, AccessTokenRequired):
            # Always raise for revoked tokens and wrong token types
            raise
        except JWTHarmonyException:
            # For optional, we don't raise other exceptions
            self._token = None
