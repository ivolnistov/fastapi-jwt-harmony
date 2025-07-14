from datetime import datetime, timedelta, timezone

import jwt
import pytest

from fastapi_jwt_harmony import JWTHarmony
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from tests.user_models import SimpleUser


def test_create_access_token(authorize_fixture):
    # Reset configuration
    JWTHarmony._config = None
    JWTHarmony._user_model_class = SimpleUser

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_access_token_expires=2, authjwt_refresh_token_expires=4))

    with pytest.raises(TypeError, match=r'missing 1 required positional argument'):
        authorize_fixture.create_access_token()

    # Test with invalid user_claims type
    with pytest.raises(TypeError, match=r'user_claims must be a Pydantic BaseModel'):
        authorize_fixture.create_access_token(user_claims='not a model')

    with pytest.raises(TypeError, match=r'fresh must be a bool'):
        user = SimpleUser(id='test')
        authorize_fixture.create_access_token(user_claims=user, fresh='lol')

    with pytest.raises(TypeError, match=r'headers must be a dictionary'):
        user = SimpleUser(id='1')
        authorize_fixture.create_access_token(user_claims=user, headers='test')


def test_create_refresh_token(authorize_fixture):
    with pytest.raises(TypeError, match=r'missing 1 required positional argument'):
        authorize_fixture.create_refresh_token()

    # Test with invalid user_claims type
    with pytest.raises(TypeError, match=r'user_claims must be a Pydantic BaseModel'):
        authorize_fixture.create_refresh_token(user_claims='not a model')

    with pytest.raises(TypeError, match=r'headers must be a dictionary'):
        user = SimpleUser(id='1')
        authorize_fixture.create_refresh_token(user_claims=user, headers='test')


def test_create_dynamic_access_token_expires(authorize_fixture):
    user = SimpleUser(id='1')
    expires_time = int(datetime.now(timezone.utc).timestamp()) + 90
    token = authorize_fixture.create_access_token(user_claims=user, expires_time=90)
    assert jwt.decode(token, 'testing', algorithms='HS256')['exp'] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 86400
    token = authorize_fixture.create_access_token(user_claims=user, expires_time=timedelta(days=1))
    assert jwt.decode(token, 'testing', algorithms='HS256')['exp'] == expires_time

    user = SimpleUser(id='1')
    token = authorize_fixture.create_access_token(user_claims=user, expires_time=False)
    assert 'exp' not in jwt.decode(token, 'testing', algorithms='HS256')


def test_create_dynamic_refresh_token_expires(authorize_fixture):
    user = SimpleUser(id='1')
    expires_time = int(datetime.now(timezone.utc).timestamp()) + 90
    token = authorize_fixture.create_refresh_token(user_claims=user, expires_time=90)
    assert jwt.decode(token, 'testing', algorithms='HS256')['exp'] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 86400
    token = authorize_fixture.create_refresh_token(user_claims=user, expires_time=timedelta(days=1))
    assert jwt.decode(token, 'testing', algorithms='HS256')['exp'] == expires_time

    user = SimpleUser(id='1')
    token = authorize_fixture.create_refresh_token(user_claims=user, expires_time=False)
    assert 'exp' not in jwt.decode(token, 'testing', algorithms='HS256')


def test_create_token_invalid_type_data_audience(authorize_fixture):
    user = SimpleUser(id='1')
    with pytest.raises(TypeError, match=r'audience'):
        authorize_fixture.create_access_token(user_claims=user, audience=1)

    with pytest.raises(TypeError, match=r'audience'):
        authorize_fixture.create_refresh_token(user_claims=user, audience=1)


def test_create_token_invalid_algorithm(authorize_fixture):
    # Reset configuration to test with a different algorithm
    JWTHarmony._config = None
    JWTHarmony._user_model_class = SimpleUser

    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            authjwt_secret_key='testing',
            authjwt_algorithm='RS256',  # Asymmetric without keys
        ),
    )

    user = SimpleUser(id='1')
    with pytest.raises(RuntimeError, match=r'Missing dependencies|authjwt_private_key'):
        authorize_fixture.create_access_token(user_claims=user, algorithm='RS256')

    with pytest.raises(RuntimeError, match=r'Missing dependencies|authjwt_private_key'):
        authorize_fixture.create_refresh_token(user_claims=user, algorithm='RS256')


def test_create_token_invalid_type_data_algorithm(authorize_fixture):
    user = SimpleUser(id='1')
    with pytest.raises(TypeError, match=r'algorithm'):
        authorize_fixture.create_access_token(user_claims=user, algorithm=1)

    with pytest.raises(TypeError, match=r'algorithm'):
        authorize_fixture.create_refresh_token(user_claims=user, algorithm=1)


def test_create_token_invalid_user_claims(authorize_fixture):
    # The new API doesn't accept subject parameter, so we test invalid user_claims types
    with pytest.raises(TypeError, match=r'user_claims must be a Pydantic BaseModel'):
        authorize_fixture.create_access_token(user_claims='asd')

    with pytest.raises(TypeError, match=r'user_claims must be a Pydantic BaseModel'):
        authorize_fixture.create_refresh_token(user_claims='asd')


def test_create_valid_user_claims(authorize_fixture):
    # Reset configuration
    JWTHarmony._config = None
    JWTHarmony._user_model_class = SimpleUser

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing'))

    # Create a user with additional claims in the model
    class ExtendedUser(SimpleUser):
        my_access: str = 'yeah'
        my_refresh: str = 'hello'

    JWTHarmony._user_model_class = ExtendedUser
    user = ExtendedUser(id='1')

    access_token = authorize_fixture.create_access_token(user_claims=user)
    refresh_token = authorize_fixture.create_refresh_token(user_claims=user)

    access_payload = jwt.decode(access_token, 'testing', algorithms='HS256')
    refresh_payload = jwt.decode(refresh_token, 'testing', algorithms='HS256')

    assert access_payload['my_access'] == 'yeah'
    assert refresh_payload['my_refresh'] == 'hello'
    assert access_payload['sub'] == '1'
    assert refresh_payload['sub'] == '1'
