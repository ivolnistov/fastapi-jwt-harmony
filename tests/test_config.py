from datetime import timedelta

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ValidationError

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyDep
from fastapi_jwt_harmony.config import JWTHarmonyConfig

from .user_models import SimpleUser


@pytest.fixture(scope='function')
def client():
    app = FastAPI()

    @app.get('/protected')
    def protected(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'hello': 'world'}

    client = TestClient(app)
    return client


def test_default_config():
    config = JWTHarmonyConfig()
    assert config.authjwt_token_location == frozenset(['cookies'])
    assert config.authjwt_secret_key is None
    assert config.authjwt_public_key is None
    assert config.authjwt_private_key is None
    assert config.authjwt_algorithm == 'HS256'
    assert config.authjwt_decode_algorithms is None
    assert config.authjwt_decode_leeway == 0
    assert config.authjwt_encode_issuer is None
    assert config.authjwt_decode_issuer is None
    assert config.authjwt_decode_audience is None
    assert config.authjwt_denylist_enabled is False
    assert config.authjwt_denylist_token_checks == {'access', 'refresh'}
    assert config.authjwt_header_name == 'Authorization'
    assert config.authjwt_header_type == 'Bearer'
    assert config.authjwt_access_token_expires == timedelta(minutes=15).total_seconds()
    assert config.authjwt_refresh_token_expires == timedelta(days=30).total_seconds()
    assert config.authjwt_access_cookie_key == 'access_token_cookie'
    assert config.authjwt_refresh_cookie_key == 'refresh_token_cookie'
    assert config.authjwt_access_cookie_path == '/'
    assert config.authjwt_refresh_cookie_path == '/'
    assert config.authjwt_cookie_max_age is None
    assert config.authjwt_cookie_domain is None
    assert config.authjwt_cookie_secure is False
    assert config.authjwt_cookie_samesite is None
    assert config.authjwt_cookie_csrf_protect is True
    assert config.authjwt_access_csrf_cookie_key == 'csrf_access_token'
    assert config.authjwt_refresh_csrf_cookie_key == 'csrf_refresh_token'
    assert config.authjwt_access_csrf_cookie_path == '/'
    assert config.authjwt_refresh_csrf_cookie_path == '/'
    assert config.authjwt_access_csrf_header_name == 'X-CSRF-Token'
    assert config.authjwt_refresh_csrf_header_name == 'X-CSRF-Token'
    assert config.authjwt_csrf_methods == {'POST', 'PUT', 'DELETE', 'PATCH'}


def test_token_expired_false():
    with pytest.raises(ValidationError, match='authjwt_access_token_expires'):
        JWTHarmonyConfig(authjwt_access_token_expires=True)

    with pytest.raises(ValidationError, match='authjwt_refresh_token_expires'):
        JWTHarmonyConfig(authjwt_refresh_token_expires=True)


def test_not_configured():
    # Test that creating instance without configure() raises error
    JWTHarmony._config = None
    with pytest.raises(RuntimeError, match='JWTHarmony is not configured'):
        JWTHarmony[SimpleUser]()


def test_secret_key_not_exist(client):
    # Reset config first
    JWTHarmony._config = None

    # Test will fail when trying to create token without secret key
    with pytest.raises(RuntimeError, match='authjwt_secret_key'):
        JWTHarmony.configure(SimpleUser, JWTHarmonyConfig())
        auth = JWTHarmony[SimpleUser]()
        user = SimpleUser(id='test')
        auth.create_access_token(user_claims=user)


def test_denylist_enabled_without_callback():
    # Reset configuration
    JWTHarmony._config = None
    JWTHarmony._token_in_denylist_callback = None  # Reset callback
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret-key', authjwt_denylist_enabled=True, authjwt_token_location='headers'))

    # Test that creating an JWTHarmony instance itself triggers the error when denylist is enabled without callback
    auth = JWTHarmony[SimpleUser]()
    user = SimpleUser(id='test')
    access_token = auth.create_access_token(user_claims=user)

    # Set the token manually and then call jwt_required
    auth._token = access_token

    # The error should occur when jwt_required is called, which triggers the denylist check
    with pytest.raises(RuntimeError, match='token_in_denylist_callback must be provided'):
        auth.jwt_required()


def test_load_config_from_model():
    class Settings(BaseModel):
        authjwt_secret_key: str = 'secret-key'
        authjwt_denylist_enabled: bool = False
        authjwt_denylist_token_checks: set = {'access', 'refresh'}

    settings = Settings()
    # Create JWTHarmonyConfig from the settings model
    config = JWTHarmonyConfig(**settings.model_dump())
    JWTHarmony.configure(SimpleUser, config)

    config = JWTHarmony._config
    assert config.authjwt_secret_key == 'secret-key'
    assert config.authjwt_denylist_enabled is False
    assert config.authjwt_denylist_token_checks == {'access', 'refresh'}


def test_load_config_with_different_algorithm():
    JWTHarmony._config = None

    class Settings(BaseModel):
        authjwt_algorithm: str = 'RS256'
        authjwt_public_key: str = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7FJV6a6sO0hXz6v+i8XI
NkUggqKBmXy3W9D8L0NIdj5PY9YFMGA32xs2TxcSZnvB1r3Y3HXLnXKu0yDoIHKS
ANhhkIdHBrOLnjQQT1OcGqskBkSQ2bQZbNjJtbGEqPl4KIMFxuuXN8JAHr8xIcZZ
9SlcrtvT/7Cqb7j7lPORG3iZFgFncxCGZ8TfGyT1nu+42Evlr0vdFBWSYl7BpDMF
s70mTrFZ6CoIaH7d9p4JHZ2p/kFTTNBYW+2RA0pPdDbZsq1capQU5kLz6e2Aucp5
f8kFqCDa3HO6aXFNbQxIPe5oaOJ3rHYQEKL4mdvs+wD8iWnnSH8vc38gfiKnrbF1
owIDAQAB
-----END PUBLIC KEY-----"""
        authjwt_private_key: str = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7FJV6a6sO0hXz6v+i8XINkUggqKBmXy3W9D8L0NIdj5PY9YF
MGA32xs2TxcSZnvB1r3Y3HXLnXKu0yDoIHKSANhhkIdHBrOLnjQQT1OcGqskBkSQ
2bQZbNjJtbGEqPl4KIMFxuuXN8JAHr8xIcZZ9SlcrtvT/7Cqb7j7lPORG3iZFgFn
cxCGZ8TfGyT1nu+42Evlr0vdFBWSYl7BpDMFs70mTrFZ6CoIaH7d9p4JHZ2p/kFT
TNBYW+2RA0pPdDbZsq1capQU5kLz6e2Aucp5f8kFqCDa3HO6aXFNbQxIPe5oaOJ3
rHYQEKL4mdvs+wD8iWnnSH8vc38gfiKnrbF1owIDAQABAoIBAG0mPaZQ2p+hPNgQ
F5b1ehTqQhvfTJoKkg2etVCuXLJAL0VqQYQvDJdXcQdeptdaBvCa8G+qG7S7AoQn
Wv2xKzQzP5n9J8M8wp3jy5IdRH3DbG8F8YFBtFPIUXZHNGWtqDHHfQZ6nqxDHkPi
aGx7EYbiHe7l2dZrDvR5gFaQBncvIIKNLIdLOSQ5qZL7/7Y7Y+Lp0dOBailGnqnO
2I4XsSG7WkYkc0bgQ8xnLxy3PKY7RMvFgF7ThDLO2QVWM13L6hBhK2oPvGlh9Yf/
8HZIB1NelqL0qP8HNA/h/C7wEd7tAB5wp0s1xQ31lyc/j6sYtsKKQhwcrUFcJlkL
KzJqYAECgYEA/Lc0+OLYp0EBF9MJC5ZPSXP3kmbgFQ1fN+LTJEtrKHBEaAQ1OTTD
fgkFJiR6trIpwo7ViVu+S2D8S3sGPD0g3fH6DBp1KaNBXaZzF6qvJYD9fgCL5RYb
YcEflPQH1+jCXLCJTvT4gOqwV2PNPnxFrXJxCWMfbLK9iNvf0gVegwECgYEA71yF
vu6fOAqGqzazA8EHZLT6i7gVJ0bfC6HSMbiE4ymeXvoVAYaKmFyN5iP2ue/dW+E0
tpf9+mn0TxaVlCO+Y1KaH0L8fmDiCr8EqTvvAJdFPrQTEshZQ5bmU5FeHX1yj6VH
pHIoNvb2bFHBDWDMm8/FpNVMm7krYGmquDFAbasCgYEAxmb2Kzf2xJRLvhsgtjdm
TJdZ0a8Z7oOg9ensJZJngtDf/5SreKh+xiedR7rmQ2drs1w8N0TQ7NQRT8OMfOIi
DilLGRKkfuUnPE6wQrhxFRSdcrFqaXJkFAn8G5evvlQPF9gYxW+lVKhhQGVlnsaF
FlkwUYOaX0uFMQQiHOpQdAECgYBjddW8bfxXF3OASH0fHwprlLqboWjGY9d+qf0l
+XYBEui1VhTHCNY2h3OBQ3nElu8F1hdYJBf9xQi5cosXBQ7X5Ph7J/nB+hBNqJcz
RSt8hqR1pYYU4MgJzqKQZB0QPsRK6K3h3clVJO5bUJhUiJNa5LxnUYRi3CyLJ5x2
6H6S3wKBgFwqRmwMjuXmg1n0LaK8YCB3xBLDGLJumOZ8gPuPokRLntQ3dteZK7Xt
7222BVi65lGooHHBQkiS7kyWJnJuEnd7tm5lQW/gQ8dOyqVQ2nEb0NMTlVr8NQTR
xKmhVwU63MB6uYMBBtUk4nZyZdnHiDIiTY2MNX9IqsjQQRZFmjXZ
-----END RSA PRIVATE KEY-----"""

    settings = Settings()
    config = JWTHarmonyConfig(**settings.model_dump())
    JWTHarmony.configure(SimpleUser, config)

    config = JWTHarmony._config
    assert config.authjwt_algorithm == 'RS256'


def test_denylist_token_checks():
    with pytest.raises(ValidationError, match='authjwt_denylist_token_checks'):
        JWTHarmonyConfig(authjwt_denylist_token_checks=['access', 'invalid'])


def test_csrf_methods():
    with pytest.raises(ValidationError, match='authjwt_csrf_methods'):
        JWTHarmonyConfig(authjwt_csrf_methods=['POST', 'INVALID'])


def test_symmetric_algorithm_without_secret_key():
    # Now validation happens when creating token, not when creating config
    JWTHarmony._config = None
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_algorithm='HS256'))
    auth = JWTHarmony[SimpleUser]()
    user = SimpleUser(id='test')
    with pytest.raises(RuntimeError, match='authjwt_secret_key'):
        auth.create_access_token(user_claims=user)


def test_asymmetric_algorithm_without_keys():
    # Now validation happens when creating token, not when creating config
    JWTHarmony._config = None

    # Test will fail due to missing crypto dependencies
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_algorithm='RS256', authjwt_public_key='some_public_key'))
    auth = JWTHarmony[SimpleUser]()
    user = SimpleUser(id='test')
    with pytest.raises(RuntimeError, match='Missing dependencies|authjwt_private_key'):
        auth.create_access_token(user_claims=user)


def test_token_location_validation():
    # Test single string conversion
    config = JWTHarmonyConfig(authjwt_token_location='headers', authjwt_secret_key='test')
    assert config.authjwt_token_location == frozenset(['headers'])

    # Test list conversion
    config = JWTHarmonyConfig(authjwt_token_location=['headers', 'cookies'], authjwt_secret_key='test')
    assert config.authjwt_token_location == frozenset(['headers', 'cookies'])

    # Test tuple conversion
    config = JWTHarmonyConfig(authjwt_token_location=('cookies',), authjwt_secret_key='test')
    assert config.authjwt_token_location == frozenset(['cookies'])

    # Test set conversion
    config = JWTHarmonyConfig(authjwt_token_location={'headers'}, authjwt_secret_key='test')
    assert config.authjwt_token_location == frozenset(['headers'])

    # Test duplicate removal
    config = JWTHarmonyConfig(authjwt_token_location=['headers', 'headers', 'cookies'], authjwt_secret_key='test')
    assert config.authjwt_token_location == frozenset(['headers', 'cookies'])

    # Test invalid location
    with pytest.raises(ValidationError, match=r'Invalid token location.*'):
        JWTHarmonyConfig(authjwt_token_location='invalid', authjwt_secret_key='test')

    # Test empty location
    with pytest.raises(ValidationError, match=r'Token location cannot be empty'):
        JWTHarmonyConfig(authjwt_token_location=[], authjwt_secret_key='test')

    # Test invalid type
    with pytest.raises(ValidationError, match=r'Token location must be a string.*'):
        JWTHarmonyConfig(authjwt_token_location=123, authjwt_secret_key='test')


def test_dict_config_basic_functionality():
    """Test that dict configuration works for basic authentication flow."""
    # Configure with dictionary instead of JWTHarmonyConfig object
    JWTHarmony.configure(
        SimpleUser,
        {
            'authjwt_secret_key': 'super-secret-key-for-testing',
            'authjwt_token_location': {'headers'},
            'authjwt_access_token_expires': 900,  # 15 minutes
            'authjwt_algorithm': 'HS256',
        },
    )

    # Create auth instance to test token creation
    auth = JWTHarmony[SimpleUser]()
    user = SimpleUser(id='123', username='testuser')
    access_token = auth.create_access_token(user_claims=user)

    # Verify token was created
    assert access_token is not None
    assert isinstance(access_token, str)

    # Verify we can decode the token
    auth._token = access_token
    auth.jwt_required()
    user_claims = auth.user_claims

    assert user_claims is not None
    assert user_claims.id == '123'
    assert user_claims.username == 'testuser'


def test_dict_config_vs_object_config():
    """Test that dict config produces same result as JWTHarmonyConfig object."""
    # Test with dictionary config
    config_dict = {
        'authjwt_secret_key': 'test-secret',
        'authjwt_token_location': {'headers'},
        'authjwt_access_token_expires': 1800,
        'authjwt_algorithm': 'HS256',
    }

    JWTHarmony.configure(SimpleUser, config_dict)
    dict_config = JWTHarmony._config

    # Test with JWTHarmonyConfig object
    config_object = JWTHarmonyConfig(
        authjwt_secret_key='test-secret', authjwt_token_location={'headers'}, authjwt_access_token_expires=1800, authjwt_algorithm='HS256'
    )

    JWTHarmony.configure(SimpleUser, config_object)
    object_config = JWTHarmony._config

    # Compare key fields
    assert dict_config.authjwt_secret_key == object_config.authjwt_secret_key
    assert dict_config.authjwt_token_location == object_config.authjwt_token_location
    assert dict_config.authjwt_access_token_expires == object_config.authjwt_access_token_expires
    assert dict_config.authjwt_algorithm == object_config.authjwt_algorithm


def test_dict_config_with_complex_types():
    """Test dict configuration with complex field types."""
    config_dict = {
        'authjwt_secret_key': 'test-secret',
        'authjwt_token_location': ['headers', 'cookies'],  # List should be converted to frozenset
        'authjwt_denylist_token_checks': ['access', 'refresh'],  # List should be converted to set
        'authjwt_csrf_methods': ['POST', 'PUT', 'DELETE'],  # List should be converted to set
        'authjwt_cookie_csrf_protect': True,
        'authjwt_access_token_expires': 3600,
    }

    JWTHarmony.configure(SimpleUser, config_dict)
    config = JWTHarmony._config

    # Verify type conversions
    assert isinstance(config.authjwt_token_location, frozenset)
    assert config.authjwt_token_location == {'headers', 'cookies'}

    assert isinstance(config.authjwt_denylist_token_checks, set)
    assert config.authjwt_denylist_token_checks == {'access', 'refresh'}

    assert isinstance(config.authjwt_csrf_methods, set)
    assert config.authjwt_csrf_methods == {'POST', 'PUT', 'DELETE'}


def test_dict_config_invalid_field():
    """Test that invalid fields in dict config are ignored (Pydantic behavior)."""
    config_dict = {
        'authjwt_secret_key': 'test-secret',
        'invalid_field': 'invalid_value',  # This will be ignored by Pydantic
    }

    # Pydantic ignores extra fields by default, so this should work
    JWTHarmony.configure(SimpleUser, config_dict)
    config = JWTHarmony._config
    assert config.authjwt_secret_key == 'test-secret'


def test_dict_config_with_none_values():
    """Test dict configuration with None values that are optional."""
    config_dict = {
        'authjwt_secret_key': 'test-secret',
        'authjwt_public_key': None,  # Optional field, None is allowed
        'authjwt_private_key': None,  # Optional field, None is allowed
    }

    JWTHarmony.configure(SimpleUser, config_dict)
    config = JWTHarmony._config

    # None values should be preserved for optional fields
    assert config.authjwt_public_key is None
    assert config.authjwt_private_key is None


def test_empty_dict_config():
    """Test configuration with empty dictionary uses all defaults."""
    # Reset config first to avoid interference from previous tests
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, {})
    config = JWTHarmony._config

    # Should use all default values (empty dict creates default config)
    assert config is not None
    assert config.authjwt_secret_key is None
    assert config.authjwt_algorithm == 'HS256'
    assert config.authjwt_token_location == frozenset({'cookies'})  # Default is cookies
    assert config.authjwt_header_name == 'Authorization'
    assert config.authjwt_header_type == 'Bearer'


def test_dict_config_immutability():
    """Test that modifying original dict doesn't affect config."""
    config_dict = {'authjwt_secret_key': 'original-secret', 'authjwt_algorithm': 'HS256'}

    JWTHarmony.configure(SimpleUser, config_dict)
    original_secret = JWTHarmony._config.authjwt_secret_key

    # Modify original dict
    config_dict['authjwt_secret_key'] = 'modified-secret'

    # Config should not be affected
    assert JWTHarmony._config.authjwt_secret_key == original_secret
    assert JWTHarmony._config.authjwt_secret_key == 'original-secret'
