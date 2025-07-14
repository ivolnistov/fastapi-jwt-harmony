"""FastAPI JWT authentication module - backward compatibility wrapper."""

# Import everything from the new modular structure
# Re-export dependency functions for backward compatibility
from fastapi import Query, Request, Response

from .base import UserModelT
from .fastapi_auth import JWTHarmony
from .websocket_auth import JWTHarmonyWS

__all__ = ['JWTHarmony', 'JWTHarmonyWS']


# HTTP dependency functions
def _jwt_required_dependency(request: Request, response: Response) -> JWTHarmony[UserModelT]:
    """Dependency with automatic jwt_required() check."""
    instance: JWTHarmony[UserModelT] = JWTHarmony(req=request, res=response)
    instance.jwt_required()
    return instance


def _jwt_optional_dependency(request: Request, response: Response) -> JWTHarmony[UserModelT]:
    """Dependency with automatic jwt_optional() check."""
    instance: JWTHarmony[UserModelT] = JWTHarmony(req=request, res=response)
    instance.jwt_optional()
    return instance


def _jwt_refresh_dependency(request: Request, response: Response) -> JWTHarmony[UserModelT]:
    """Dependency with automatic refresh token check."""
    instance: JWTHarmony[UserModelT] = JWTHarmony(req=request, res=response)
    instance.jwt_refresh_token_required()
    return instance


def _jwt_fresh_dependency(request: Request, response: Response) -> JWTHarmony[UserModelT]:
    """Dependency with automatic fresh token check."""
    instance: JWTHarmony[UserModelT] = JWTHarmony(req=request, res=response)
    instance.fresh_jwt_required()
    return instance


def _jwt_bare_dependency(request: Request, response: Response) -> JWTHarmony[UserModelT]:
    """Dependency without automatic JWT checks - for token creation endpoints."""
    return JWTHarmony(req=request, res=response)


# WebSocket dependency functions
def _jwt_websocket_dependency() -> JWTHarmonyWS[UserModelT]:
    """WebSocket dependency - no automatic JWT checks, manual validation required."""
    return JWTHarmonyWS()


def _jwt_websocket_required_dependency(token: str = Query(...)) -> JWTHarmonyWS[UserModelT]:
    """WebSocket dependency with automatic jwt_required() check."""
    instance: JWTHarmonyWS[UserModelT] = JWTHarmonyWS()
    instance.jwt_required(token)
    return instance


def _jwt_websocket_optional_dependency(token: str = Query('')) -> JWTHarmonyWS[UserModelT]:
    """WebSocket dependency with automatic jwt_optional() check."""
    instance: JWTHarmonyWS[UserModelT] = JWTHarmonyWS()
    instance.jwt_optional(token)
    return instance


def _jwt_websocket_refresh_dependency(token: str = Query(...)) -> JWTHarmonyWS[UserModelT]:
    """WebSocket dependency with automatic refresh token check."""
    instance: JWTHarmonyWS[UserModelT] = JWTHarmonyWS()
    instance.jwt_refresh_token_required(token)
    return instance


def _jwt_websocket_fresh_dependency(token: str = Query(...)) -> JWTHarmonyWS[UserModelT]:
    """WebSocket dependency with automatic fresh token check."""
    instance: JWTHarmonyWS[UserModelT] = JWTHarmonyWS()
    instance.fresh_jwt_required(token)
    return instance


# Ready-to-use dependency instances for convenience
JWTHarmonyDep = _jwt_required_dependency
JWTHarmonyOptional = _jwt_optional_dependency
JWTHarmonyRefresh = _jwt_refresh_dependency
JWTHarmonyFresh = _jwt_fresh_dependency
JWTHarmonyBare = _jwt_bare_dependency
JWTHarmonyWebSocket = _jwt_websocket_dependency

# WebSocket-specific dependencies
JWTHarmonyWebSocketDep = _jwt_websocket_required_dependency
JWTHarmonyWebSocketOptional = _jwt_websocket_optional_dependency
JWTHarmonyWebSocketRefresh = _jwt_websocket_refresh_dependency
JWTHarmonyWebSocketFresh = _jwt_websocket_fresh_dependency
