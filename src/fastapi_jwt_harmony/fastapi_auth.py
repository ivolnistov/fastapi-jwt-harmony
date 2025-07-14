"""HTTP (FastAPI) JWT authentication implementation."""

import hmac
from typing import Literal, Optional

from fastapi import Request, Response

from .base import JWTHarmonyBase, UserModelT
from .exceptions import AccessTokenRequired, CSRFError, JWTDecodeError, JWTHarmonyException, MissingTokenError, RevokedTokenError


class JWTHarmony(JWTHarmonyBase[UserModelT]):
    """
    HTTP-specific JWT authentication implementation for FastAPI.

    This class handles JWT authentication for regular HTTP requests
    with support for both header and cookie-based authentication.
    """

    def __init__(self, req: Optional[Request] = None, res: Optional[Response] = None) -> None:
        """
        Initialize HTTP JWT handler.

        Args:
            req: The incoming FastAPI request object
            res: The outgoing FastAPI response object
        """
        super().__init__()
        self._request = req
        self._response = res

        # Extract token from headers if present
        if req and self.jwt_in_headers:
            if auth := req.headers.get(self.config.authjwt_header_name):
                self._get_jwt_from_headers(auth)

    def jwt_required(self) -> None:
        """
        Verify that a valid access token is present in the request.

        Checks both headers and cookies based on configuration.

        Raises:
            MissingTokenError: If no token is found
            Various JWT exceptions on validation failure
        """
        # Try headers first if enabled
        if self.jwt_in_headers:
            if self.token:
                try:
                    self._verify_jwt_in_request(self.token, 'access', 'headers')
                    return  # Success
                except MissingTokenError:
                    if not self.jwt_in_cookies:
                        raise  # Re-raise if cookies are not enabled
                    # Continue to check cookies
            else:
                # No token in headers
                if not self.jwt_in_cookies:
                    raise MissingTokenError(f'Missing {self.config.authjwt_header_name} Header')
                # Continue to check cookies

        # Try cookies if enabled
        if self.jwt_in_cookies:
            if self._request is None:
                raise RuntimeError('Request object is required for cookie authentication')
            self._verify_and_get_jwt_in_cookies('access', self._request)

    def jwt_optional(self) -> None:
        """
        Optionally verify JWT token if present in the request.

        Does not raise exceptions if token is missing or invalid, except for revoked tokens.
        """
        # Try headers first if enabled
        if self.jwt_in_headers and self.token:
            try:
                self._verify_jwt_in_request(self.token, 'access', 'headers')
                return  # Success
            except (RevokedTokenError, AccessTokenRequired):
                # Always raise for revoked tokens and wrong token types, even in optional mode
                raise
            except JWTHarmonyException:
                # For optional, we don't raise other exceptions
                self._token = None

        # Try cookies if enabled
        if self.jwt_in_cookies and self._request:
            self._verify_and_get_jwt_optional_in_cookies(self._request)

    def jwt_refresh_token_required(self) -> None:
        """
        Verify that a valid refresh token is present in the request.

        Checks both headers and cookies based on configuration.

        Raises:
            MissingTokenError: If no token is found
            RefreshTokenRequired: If token is not a refresh token
            Various JWT exceptions on validation failure
        """
        # Try headers first if enabled
        if self.jwt_in_headers:
            if self.token:
                try:
                    self._verify_jwt_in_request(self.token, 'refresh', 'headers')
                    return  # Success
                except MissingTokenError:
                    if not self.jwt_in_cookies:
                        raise  # Re-raise if cookies are not enabled
                    # Continue to check cookies
            else:
                # No token in headers
                if not self.jwt_in_cookies:
                    raise MissingTokenError(f'Missing {self.config.authjwt_header_name} Header')
                # Continue to check cookies

        # Try cookies if enabled
        if self.jwt_in_cookies:
            if self._request is None:
                raise RuntimeError('Request object is required for cookie authentication')
            self._verify_and_get_jwt_in_cookies('refresh', self._request)

    def fresh_jwt_required(self) -> None:
        """
        Verify that a valid fresh access token is present in the request.

        Checks both headers and cookies based on configuration.

        Raises:
            MissingTokenError: If no token is found
            FreshTokenRequired: If token is not fresh
            Various JWT exceptions on validation failure
        """
        # Try headers first if enabled
        if self.jwt_in_headers:
            if self.token:
                try:
                    self._verify_jwt_in_request(self.token, 'access', 'headers', fresh=True)
                    return  # Success
                except MissingTokenError:
                    if not self.jwt_in_cookies:
                        raise  # Re-raise if cookies are not enabled
                    # Continue to check cookies
            else:
                # No token in headers
                if not self.jwt_in_cookies:
                    raise MissingTokenError(f'Missing {self.config.authjwt_header_name} Header')
                # Continue to check cookies

        # Try cookies if enabled
        if self.jwt_in_cookies:
            if self._request is None:
                raise RuntimeError('Request object is required for cookie authentication')
            self._verify_and_get_jwt_in_cookies('access', self._request, fresh=True)

    def set_access_cookies(self, encoded_access_token: str, response: Optional[Response] = None, max_age: Optional[int] = None) -> None:
        """
        Set access token cookies with optional CSRF protection.

        Args:
            encoded_access_token: The encoded JWT access token
            response: Optional response object (uses instance response if not provided)
            max_age: Optional max age for the cookie in seconds
        """
        response = response or self._response
        if not response:
            raise RuntimeError('Response object is required to set cookies')

        if not isinstance(response, Response):
            raise TypeError('response must be a Response object')

        if max_age is not None and not isinstance(max_age, int):
            raise TypeError('max_age must be an int')

        # Set main access token cookie
        cookie_key = self.config.authjwt_access_cookie_key
        response.set_cookie(
            key=cookie_key,
            value=encoded_access_token,
            max_age=max_age or self.config.authjwt_cookie_max_age,
            path=self.config.authjwt_access_cookie_path,
            domain=self.config.authjwt_cookie_domain,
            secure=self.config.authjwt_cookie_secure,
            httponly=True,
            samesite=self.config.authjwt_cookie_samesite,
        )

        # Set CSRF cookie if protection is enabled
        if self.config.authjwt_cookie_csrf_protect:
            self._set_csrf_cookie(encoded_access_token, response, 'access')

    def set_refresh_cookies(self, encoded_refresh_token: str, response: Optional[Response] = None, max_age: Optional[int] = None) -> None:
        """
        Set refresh token cookies with optional CSRF protection.

        Args:
            encoded_refresh_token: The encoded JWT refresh token
            response: Optional response object (uses instance response if not provided)
            max_age: Optional max age for the cookie in seconds
        """
        response = response or self._response
        if not response:
            raise RuntimeError('Response object is required to set cookies')

        if not isinstance(response, Response):
            raise TypeError('response must be a Response object')

        if max_age is not None and not isinstance(max_age, int):
            raise TypeError('max_age must be an int')

        # Set main refresh token cookie
        cookie_key = self.config.authjwt_refresh_cookie_key
        response.set_cookie(
            key=cookie_key,
            value=encoded_refresh_token,
            max_age=max_age or self.config.authjwt_cookie_max_age,
            path=self.config.authjwt_refresh_cookie_path,
            domain=self.config.authjwt_cookie_domain,
            secure=self.config.authjwt_cookie_secure,
            httponly=True,
            samesite=self.config.authjwt_cookie_samesite,
        )

        # Set CSRF cookie if protection is enabled
        if self.config.authjwt_cookie_csrf_protect:
            self._set_csrf_cookie(encoded_refresh_token, response, 'refresh')

    def unset_jwt_cookies(self, response: Optional[Response] = None) -> None:
        """
        Unset all JWT cookies (access, refresh, and CSRF).

        Args:
            response: Optional response object (uses instance response if not provided)
        """
        self.unset_access_cookies(response)
        self.unset_refresh_cookies(response)

    def unset_access_cookies(self, response: Optional[Response] = None) -> None:
        """
        Unset access token cookies.

        Args:
            response: Optional response object (uses instance response if not provided)
        """
        response = response or self._response
        if not response:
            raise RuntimeError('Response object is required to unset cookies')

        if not isinstance(response, Response):
            raise TypeError('response must be a Response object')

        # Unset main access token cookie
        cookie_key = self.config.authjwt_access_cookie_key
        response.delete_cookie(key=cookie_key, path=self.config.authjwt_access_cookie_path, domain=self.config.authjwt_cookie_domain)

        # Unset CSRF cookie
        csrf_key = self.config.authjwt_access_csrf_cookie_key
        response.delete_cookie(key=csrf_key, path=self.config.authjwt_access_cookie_path, domain=self.config.authjwt_cookie_domain)

    def unset_refresh_cookies(self, response: Optional[Response] = None) -> None:
        """
        Unset refresh token cookies.

        Args:
            response: Optional response object (uses instance response if not provided)
        """
        response = response or self._response
        if not response:
            raise RuntimeError('Response object is required to unset cookies')

        if not isinstance(response, Response):
            raise TypeError('response must be a Response object')

        # Unset main refresh token cookie
        cookie_key = self.config.authjwt_refresh_cookie_key
        response.delete_cookie(key=cookie_key, path=self.config.authjwt_refresh_cookie_path, domain=self.config.authjwt_cookie_domain)

        # Unset CSRF cookie
        csrf_key = self.config.authjwt_refresh_csrf_cookie_key
        response.delete_cookie(key=csrf_key, path=self.config.authjwt_refresh_cookie_path, domain=self.config.authjwt_cookie_domain)

    def _set_csrf_cookie(self, encoded_token: str, response: Response, token_type: Literal['access', 'refresh']) -> None:
        """
        Set CSRF protection cookie.

        Args:
            encoded_token: The encoded JWT token
            response: Response object to set cookie on
            token_type: Type of token (access or refresh)
        """
        # Decode token to get CSRF value
        decoded = self.get_raw_jwt(encoded_token)
        if not decoded or 'csrf' not in decoded:
            return

        csrf_value = decoded['csrf']

        # Determine cookie key and path
        if token_type == 'access':
            cookie_key = self.config.authjwt_access_csrf_cookie_key
            cookie_path = self.config.authjwt_access_cookie_path
        else:
            cookie_key = self.config.authjwt_refresh_csrf_cookie_key
            cookie_path = self.config.authjwt_refresh_cookie_path

        # Set CSRF cookie (not httponly so JS can read it)
        response.set_cookie(
            key=cookie_key,
            value=str(csrf_value),
            max_age=self.config.authjwt_cookie_max_age,
            path=cookie_path,
            domain=self.config.authjwt_cookie_domain,
            secure=self.config.authjwt_cookie_secure,
            httponly=False,  # Must be False for CSRF
            samesite=self.config.authjwt_cookie_samesite,
        )

    def _verify_and_get_jwt_in_cookies(self, type_token: Literal['access', 'refresh'], request: Request, fresh: bool = False) -> None:
        """
        Verify and extract JWT from cookies with CSRF protection.

        Args:
            type_token: Type of token to verify
            request: The request object containing cookies
            fresh: Whether to require a fresh token
        """
        # Determine cookie key
        if type_token == 'access':
            cookie_key = self.config.authjwt_access_cookie_key
            csrf_header_name = self.config.authjwt_access_csrf_header_name
        else:
            cookie_key = self.config.authjwt_refresh_cookie_key
            csrf_header_name = self.config.authjwt_refresh_csrf_header_name

        # Extract token from cookies
        cookie = request.cookies.get(cookie_key)
        if not cookie:
            raise MissingTokenError(f'Missing cookie {cookie_key}')

        # Check CSRF protection if enabled
        if self.config.authjwt_cookie_csrf_protect:
            # Check if method requires CSRF
            if request.method in self.config.authjwt_csrf_methods:
                # Get CSRF token from header
                csrf_token = request.headers.get(csrf_header_name)
                if not csrf_token:
                    raise CSRFError('Missing CSRF Token')

                # Verify token and get CSRF from it
                self._token = cookie
                self._verify_jwt_in_request(self._token, type_token, 'cookies', fresh)

                decoded_token = self.get_raw_jwt()
                if decoded_token:
                    csrf_in_token = decoded_token.get('csrf')
                    if not csrf_in_token:
                        raise JWTDecodeError('Missing claim: csrf')

                    # Compare CSRF tokens

                    if not hmac.compare_digest(str(csrf_in_token), str(csrf_token)):
                        raise CSRFError('CSRF double submit tokens do not match')
            else:
                # Method doesn't require CSRF, just verify token
                self._token = cookie
                self._verify_jwt_in_request(self._token, type_token, 'cookies', fresh)
        else:
            # No CSRF protection, just verify token
            self._token = cookie
            self._verify_jwt_in_request(self._token, type_token, 'cookies', fresh)

    def _verify_and_get_jwt_optional_in_cookies(self, request: Request) -> None:
        """
        Optionally verify JWT from cookies.

        Does not raise exceptions if token is missing or invalid.

        Args:
            request: The request object containing cookies
        """
        # Try to get access token from cookies
        cookie_key = self.config.authjwt_access_cookie_key
        cookie = request.cookies.get(cookie_key)

        if not cookie:
            # No token, but that's OK for optional
            return

        try:
            # Check CSRF if enabled and method requires it
            if self.config.authjwt_cookie_csrf_protect and request.method in self.config.authjwt_csrf_methods:
                csrf_header_name = self.config.authjwt_access_csrf_header_name
                csrf_token = request.headers.get(csrf_header_name)

                if not csrf_token:
                    # No CSRF token, treat as no auth
                    return

                # Verify token
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

                    if not hmac.compare_digest(str(csrf_in_token), str(csrf_token)):
                        # CSRF mismatch, treat as no auth
                        self._token = None
                        return
            else:
                # No CSRF protection or method doesn't require it
                self._token = cookie
                self._verify_jwt_in_request(self._token, 'access', 'cookies')
        except (RevokedTokenError, AccessTokenRequired):
            # Always raise for revoked tokens and wrong token types, even in optional mode
            raise
        except JWTHarmonyException:
            # For optional, we don't raise other exceptions
            self._token = None


# Import required types
