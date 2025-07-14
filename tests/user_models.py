"""User models for testing the new Pydantic-based AuthJWT API"""

from typing import Optional

from pydantic import BaseModel


class User(BaseModel):
    """Basic user model for testing"""

    id: str
    username: Optional[str] = None
    email: Optional[str] = None
    is_active: bool = True


class SimpleUser(BaseModel):
    """Minimal user model with ID and optional username"""

    id: str
    username: Optional[str] = None
