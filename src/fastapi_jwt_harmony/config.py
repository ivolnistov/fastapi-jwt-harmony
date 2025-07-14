"""Configuration module for FastAPI JWT authentication."""

from datetime import timedelta
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


# noinspection PyMethodParameters
class JWTHarmonyConfig(BaseModel):
    """
    Configuration class for managing settings related to authentication and JSON Web Tokens
    (JWTs). This class is intended for use in setting up and validating custom JWT settings for
    specific application requirements.

    The class uses Pydantic's `BaseModel` to define, validate, and manage configuration
    variables. These settings include token locations, cryptographic keys, algorithms, cookie
    options, expiration times, and Cross-Site Request Forgery (CSRF) protection, among others.

    Attributes:
        authjwt_token_location (frozenset[Literal['headers', 'cookies']]): Defines the locations where the JWTs are stored,
            either in headers, cookies, or both.
        authjwt_secret_key (str | None): The secret key used for signing and verifying JWTs.
        authjwt_public_key (str | None): Optional public key for asymmetric signature
            validation.
        authjwt_private_key (str | None): Optional private key for asymmetric signature
            generation.
        authjwt_algorithm (str): The algorithm used for signing and decoding JWTs.
        authjwt_decode_algorithms (list[str] | None): A list of allowed decoding algorithms.
        authjwt_decode_leeway (int | timedelta): Leeway duration for clock skew when
            validating token expiration claims.
        authjwt_encode_issuer (str | None): The issuer string to include when encoding JWTs.
        authjwt_decode_issuer (str | None): The expected issuer string for decoding JWTs.
        authjwt_decode_audience (str | set[str] | None): Expected audience identifiers for
            validating tokens.
        authjwt_denylist_enabled (bool): Enables or disables the denylist feature.
        authjwt_denylist_token_checks (set[str]): Specifies which token types ('access' or
            'refresh') should be checked against the denylist.
        authjwt_header_name (str): The name of the HTTP header containing the JWT.
        authjwt_header_type (str): The type of the header, e.g., 'Bearer'.
        authjwt_access_token_expires (bool | int | timedelta | None): Expiration time for
            access tokens.
        authjwt_refresh_token_expires (bool | int | timedelta | None): Expiration time for
            refresh tokens.
        authjwt_access_cookie_key (str): Key name for the access token cookie.
        authjwt_refresh_cookie_key (str): Key name for the refresh token cookie.
        authjwt_access_cookie_path (str): Path scope of the access token cookie.
        authjwt_refresh_cookie_path (str): Path scope of the refresh token cookie.
        authjwt_cookie_max_age (int | None): The maximum age in seconds for cookies.
        authjwt_cookie_domain (str | None): Domain scope for the cookies.
        authjwt_cookie_secure (bool | None): Whether cookies require a secure connection (HTTPS).
        authjwt_cookie_samesite (str | None): SameSite attribute for cookies ('strict', 'lax',
            or 'none').
        authjwt_cookie_csrf_protect (bool): Enables or disables double-submit CSRF
            protection.
        authjwt_access_csrf_cookie_key (str): Key name for the CSRF cookie associated
            with the access token.
        authjwt_refresh_csrf_cookie_key (str): Key name for the CSRF cookie associated
            with the refresh token.
        authjwt_access_csrf_cookie_path (str): Path scope for the access token's CSRF
            cookie.
        authjwt_refresh_csrf_cookie_path (str): Path scope for the refresh token's CSRF
            cookie.
        authjwt_access_csrf_header_name (str): Name of the HTTP header carrying the CSRF
            token for access tokens.
        authjwt_refresh_csrf_header_name (str): Name of the HTTP header carrying the CSRF
            token for refresh tokens.
        authjwt_csrf_methods (set[str]): Set of HTTP methods that require CSRF validation.
    """

    authjwt_token_location: frozenset[Literal['headers', 'cookies']] = Field(frozenset(['cookies']), description='Location of the JWT (headers or cookies)')
    authjwt_secret_key: str | None = Field(None, description='Secret key for signing JWTs')
    authjwt_public_key: str | None = Field(None, description='Public key for asymmetric signature validation')
    authjwt_private_key: str | None = Field(None, description='Private key for asymmetric signature generation')
    authjwt_algorithm: str = Field('HS256', description='Algorithm for signing and decoding JWTs')
    authjwt_decode_algorithms: list[str] | None = Field(None, description='Allowed algorithms for decoding JWTs')
    authjwt_decode_leeway: int | timedelta = Field(0, description='Leeway duration for clock skew when validating token expiration claims')
    authjwt_encode_issuer: str | None = Field(None, description='Issuer claim for encoding JWTs')
    authjwt_decode_issuer: str | None = Field(None, description='Expected issuer claim for decoding JWTs')
    authjwt_decode_audience: str | set[str] | None = Field(None, description='Expected audience identifiers for validating tokens')
    authjwt_denylist_enabled: bool = Field(False, description='Enable or disable the denylist feature')
    authjwt_denylist_token_checks: set[str] = Field(
        default_factory=lambda: {'access', 'refresh'},
        description='Token types to check against the denylist',
    )
    authjwt_header_name: str = Field('Authorization', description='HTTP header name for the JWT')
    authjwt_header_type: str = Field('Bearer', description='Type of the header, e.g., Bearer')
    authjwt_access_token_expires: bool | int | timedelta = Field(
        int(timedelta(minutes=15).total_seconds()),
        description='Expiration time for access tokens',
    )
    authjwt_refresh_token_expires: bool | int | timedelta = Field(
        int(timedelta(days=30).total_seconds()),
        description='Expiration time for refresh tokens',
    )
    authjwt_access_cookie_key: str = Field('access_token_cookie', description='Key for the access token cookie')
    authjwt_refresh_cookie_key: str = Field('refresh_token_cookie', description='Key for the refresh token cookie')
    authjwt_access_cookie_path: str = Field('/', description='Path scope for the access token cookie')
    authjwt_refresh_cookie_path: str = Field('/', description='Path scope for the refresh token cookie')
    authjwt_cookie_max_age: int | None = Field(None, description='Maximum age in seconds for cookies')
    authjwt_cookie_domain: str | None = Field(None, description='Domain scope for the cookies')
    authjwt_cookie_secure: bool = Field(False, description='Require secure connection (HTTPS) for cookies')
    authjwt_cookie_samesite: Literal['strict', 'lax', 'none'] | None = Field(None, description='SameSite attribute for cookies (strict, lax, none)')

    authjwt_cookie_csrf_protect: bool = Field(True, description='Enable double-submit CSRF protection')
    authjwt_access_csrf_cookie_key: str = Field('csrf_access_token', description='Key for the CSRF cookie associated with the access token')
    authjwt_refresh_csrf_cookie_key: str = Field('csrf_refresh_token', description='Key for the CSRF cookie associated with the refresh token')
    authjwt_access_csrf_cookie_path: str = Field('/', description="Path scope for the access token's CSRF cookie")
    authjwt_refresh_csrf_cookie_path: str = Field('/', description="Path scope for the refresh token's CSRF cookie")
    authjwt_access_csrf_header_name: str = Field('X-CSRF-Token', description='HTTP header name for the CSRF token for access tokens')
    authjwt_refresh_csrf_header_name: str = Field('X-CSRF-Token', description='HTTP header name for the CSRF token for refresh tokens')
    authjwt_csrf_methods: set[str] = Field(
        default_factory=lambda: {'POST', 'PUT', 'DELETE', 'PATCH'},
        description='HTTP methods that require CSRF validation',
    )

    model_config = ConfigDict(validate_default=False, str_min_length=1, str_strip_whitespace=True)

    @field_validator('authjwt_token_location', mode='before')
    def validate_token_location(cls, v: Any) -> frozenset[Literal['headers', 'cookies']]:
        """
        Validates and converts the token location to a frozenset format.

        Accepts:
        - Single string: 'headers' or 'cookies' -> frozenset({'headers'}) or frozenset({'cookies'})
        - List of strings: ['headers', 'cookies'] -> frozenset({'headers', 'cookies'})
        - Tuple: ('headers',) or ('cookies',) or ('headers', 'cookies')
        - Set/frozenset: {'headers'} or frozenset({'cookies'})

        Args:
            v: The value to validate (string, list, tuple, set, or frozenset)

        Returns:
            frozenset: Always returns a frozenset of location strings

        Raises:
            ValueError: If invalid location is provided
        """
        valid_locations = {'headers', 'cookies'}

        if isinstance(v, str):
            if v not in valid_locations:
                raise ValueError(f"Invalid token location: {v}. Must be 'headers' or 'cookies'")
            return frozenset([v])  # type: ignore[list-item]
        if isinstance(v, (list, tuple, set, frozenset)):
            locations = set(v)
            invalid = locations - valid_locations
            if invalid:
                raise ValueError(f"Invalid token locations: {invalid}. Must be 'headers' or 'cookies'")
            if not locations:
                raise ValueError('Token location cannot be empty')
            return frozenset(locations)
        raise ValueError(f'Token location must be a string, list, tuple, set, or frozenset, got {type(v)}')

    @field_validator('authjwt_access_token_expires', 'authjwt_refresh_token_expires')
    def validate_access_token_expires(cls, v: Any, info: Any) -> bool | int | timedelta:
        """
        Validates whether the specified fields for token expiration settings only accept False as their value.

        Raises a `ValueError` if either 'authjwt_access_token_expires' or 'authjwt_refresh_token_expires'
        is set to True, as these fields are restricted to boolean False values. Ensures that incorrect or
        unsupported configurations are avoided.

        Args:
            v: The value of the field being validated. Must be False to pass validation.
            info: Contains metadata about the field being validated, including its name.

        Returns:
            The validated value if it passes the validation criteria.
        """
        if v is True:
            raise ValueError(f"The '{info.field_name}' only accept value False (bool)")
        return v  # type: ignore[no-any-return]

    @field_validator('authjwt_denylist_token_checks')
    def validate_denylist_token_checks(cls, v: Any) -> set[str]:
        """
        Validates the provided value for 'authjwt_denylist_token_checks' to ensure all elements
        in the list are either 'access' or 'refresh'. This is a field validator used for ensuring
        that the denylist token checks configuration contains only valid options.

        Args:
            v (list): List containing token types to be checked in the denylist.

        Returns:
            list: The validated list if all elements are correct.

        Raises:
            ValueError: If any element in the list is not 'access' or 'refresh'.
        """
        for i in v:
            if i not in ['access', 'refresh']:
                raise ValueError("The 'authjwt_denylist_token_checks' must be between 'access' or 'refresh'")
        return v  # type: ignore[no-any-return]

    @field_validator('authjwt_csrf_methods')
    def validate_csrf_methods(cls, v: Any) -> set[str]:
        """
        Validates the `authjwt_csrf_methods` attribute, ensuring all specified values are valid
        HTTP request methods. Converts methods to uppercase for standardization and checks
        them against a predefined set of allowed HTTP methods.

        Args:
            v (list[str]): A list of HTTP request methods to validate.

        Returns:
            set[str]: A set of validated HTTP request methods in uppercase.

        Raises:
            ValueError: If any of the methods in the input list are not valid HTTP request
                methods.
        """
        response: set[str] = set()
        for i in v:
            if i.upper() not in {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH'}:
                raise ValueError("The 'authjwt_csrf_methods' must be between http request methods")
            response.add(i.upper())
        return response
