"""JWT algorithm constants."""

from jwt.algorithms import requires_cryptography

SYMMETRIC_ALGORITHMS = {
    'HS256',
    'HS384',
    'HS512',
}
ASYMMETRIC_ALGORITHMS = requires_cryptography
