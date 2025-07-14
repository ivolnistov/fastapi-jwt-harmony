"""Utility functions for JWT operations."""

import uuid
from datetime import datetime


def get_jwt_identifier() -> str:
    """
    Generates a new unique JWT (JSON Web Token) identifier using a UUID.

    This function creates a unique identifier in the form of a string using the
    UUID4 standard, which generates a random UUID. This identifier can be used in
    JWTs to provide a unique value for the "jti" (JWT ID) claim.

    Returns:
        str: A string representation of the generated UUID4.
    """
    return str(uuid.uuid4())


def get_int_from_datetime(value: datetime) -> int:
    """
    Converts a datetime object to an integer representing its UNIX timestamp.

    This function takes a datetime object and returns its corresponding UNIX
    timestamp as an integer. The UNIX timestamp is the total number of seconds
    that have elapsed since January 1, 1970 (UTC). It ensures the input is of
    type datetime and raises a TypeError if the provided value is not.

    Args:
        value (datetime): The datetime object to be converted into a UNIX
            timestamp.

    Returns:
        int: The UNIX timestamp corresponding to the provided datetime.

    Raises:
        TypeError: If the input is not an instance of datetime.
    """
    if not isinstance(value, datetime):  # pragma: no cover
        raise TypeError('a datetime is required')
    return int(value.timestamp())
