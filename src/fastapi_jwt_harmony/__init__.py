"""FastAPI JWT authentication library with Pydantic integration - bringing harmony to your auth flow."""

from .auth_jwt import (
    JWTHarmony,
    JWTHarmonyBare,
    JWTHarmonyDep,
    JWTHarmonyFresh,
    JWTHarmonyOptional,
    JWTHarmonyRefresh,
    JWTHarmonyWebSocket,
    JWTHarmonyWebSocketDep,
    JWTHarmonyWebSocketFresh,
    JWTHarmonyWebSocketOptional,
    JWTHarmonyWebSocketRefresh,
)
from .config import JWTHarmonyConfig
from .exceptions import (
    AccessTokenRequired,
    CSRFError,
    FreshTokenRequired,
    InvalidHeaderError,
    JWTDecodeError,
    JWTHarmonyException,
    MissingTokenError,
    RefreshTokenRequired,
    RevokedTokenError,
    TokenExpired,
)
from .version import __version__
from .websocket_auth import JWTHarmonyWS

__all__ = [
    'JWTHarmony',
    'JWTHarmonyWS',
    'JWTHarmonyDep',
    'JWTHarmonyOptional',
    'JWTHarmonyRefresh',
    'JWTHarmonyFresh',
    'JWTHarmonyBare',
    'JWTHarmonyWebSocket',
    'JWTHarmonyWebSocketDep',
    'JWTHarmonyWebSocketOptional',
    'JWTHarmonyWebSocketRefresh',
    'JWTHarmonyWebSocketFresh',
    'JWTHarmonyConfig',
    'JWTHarmonyException',
    'InvalidHeaderError',
    'JWTDecodeError',
    'CSRFError',
    'MissingTokenError',
    'RevokedTokenError',
    'AccessTokenRequired',
    'RefreshTokenRequired',
    'FreshTokenRequired',
    'TokenExpired',
    '__version__',
]
