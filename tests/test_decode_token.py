import os
import time

import jwt
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from jwt.algorithms import has_crypto

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyDep, JWTHarmonyRefresh
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from fastapi_jwt_harmony.exceptions import JWTHarmonyException
from tests.user_models import SimpleUser


@pytest.fixture(scope='function')
def client():
    # Configure JWTHarmony for this test
    JWTHarmony._config = None
    JWTHarmony._user_model_class = SimpleUser
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing'))

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def authjwt_exception_handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/protected')
    def protected(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'hello': 'world'}

    @app.get('/raw_token')
    def raw_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return Authorize.get_raw_jwt()

    @app.get('/get_subject')
    def get_subject(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return Authorize.get_jwt_subject()

    @app.get('/refresh_token')
    def get_refresh_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyRefresh)):
        return Authorize.get_jwt_subject()

    client = TestClient(app)
    return client


@pytest.fixture(scope='function')
def default_access_token():
    return {
        'jti': '123',
        'sub': 'test',
        'type': 'access',
        'fresh': True,
    }


@pytest.fixture(scope='function')
def encoded_token(default_access_token):
    return jwt.encode(default_access_token, 'secret-key', algorithm='HS256')


def test_verified_token(client, encoded_token, authorize_fixture):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret-key', authjwt_access_token_expires=2, authjwt_token_location='headers'))

    # Create new JWTHarmony instance with the new config
    auth = JWTHarmony()

    # DecodeError
    response = client.get('/protected', headers={'Authorization': 'Bearer test'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Not enough segments'}
    # InvalidSignatureError
    token = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Signature verification failed'}
    # ExpiredSignatureError
    user = SimpleUser(id='test')
    token = auth.create_access_token(user_claims=user)
    time.sleep(3)
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Token expired'}
    # InvalidAlgorithmError
    token = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS384')
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'The specified alg value is not allowed'}

    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            authjwt_secret_key='secret-key',
            authjwt_access_token_expires=1,
            authjwt_refresh_token_expires=1,
            authjwt_decode_leeway=2,
            authjwt_token_location='headers',
        ),
    )

    user = SimpleUser(id='test')
    access_token = auth.create_access_token(user_claims=user)
    refresh_token = auth.create_refresh_token(user_claims=user)
    time.sleep(2)
    # JWT payload is now expired
    # But with some leeway, it will still validate
    response = client.get('/protected', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}

    response = client.get('/refresh_token', headers={'Authorization': f'Bearer {refresh_token}'})
    assert response.status_code == 200
    assert response.json() == 'test'

    # Valid Token
    response = client.get('/protected', headers={'Authorization': f'Bearer {encoded_token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}


def test_get_raw_token(client, default_access_token, encoded_token):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret-key', authjwt_token_location='headers'))

    response = client.get('/raw_token', headers={'Authorization': f'Bearer {encoded_token}'})
    assert response.status_code == 200
    assert response.json() == default_access_token


def test_get_raw_jwt(default_access_token, encoded_token):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret-key'))

    auth = JWTHarmony()
    assert auth.get_raw_jwt(encoded_token) == default_access_token


def test_get_jwt_jti(client, default_access_token, encoded_token):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret-key'))

    auth = JWTHarmony()
    auth._token = encoded_token  # Set the token directly since get_jti doesn't accept encoded_token parameter
    assert auth.get_jti() == default_access_token['jti']


def test_get_jwt_subject(client, default_access_token, encoded_token):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret-key', authjwt_token_location='headers'))

    response = client.get('/get_subject', headers={'Authorization': f'Bearer {encoded_token}'})
    assert response.status_code == 200
    assert response.json() == default_access_token['sub']


def test_invalid_jwt_issuer(client):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret-key', authjwt_token_location='headers'))

    auth = JWTHarmony()

    # No issuer claim expected or provided - OK
    user = SimpleUser(id='test')
    token = auth.create_access_token(user_claims=user)
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}

    # Set decode issuer expectation
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret-key', authjwt_token_location='headers', authjwt_decode_issuer='urn:foo'))

    # Issuer claim expected and not provided - Not OK
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Token is missing the "iss" claim'}

    # Set encode issuer to wrong value
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(authjwt_secret_key='secret-key', authjwt_token_location='headers', authjwt_decode_issuer='urn:foo', authjwt_encode_issuer='urn:bar'),
    )

    # Issuer claim still expected and wrong one provided - not OK
    auth2 = JWTHarmony()
    user = SimpleUser(id='test')
    token = auth2.create_access_token(user_claims=user)
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Invalid issuer'}


@pytest.mark.parametrize('token_aud', ['foo', ['bar'], ['foo', 'bar', 'baz']])
def test_valid_aud(client, token_aud):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(
        SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret-key', authjwt_token_location='headers', authjwt_decode_audience=['foo', 'bar'])
    )

    auth = JWTHarmony()

    user = SimpleUser(id='1')
    access_token = auth.create_access_token(user_claims=user, audience=token_aud)
    response = client.get('/protected', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}

    refresh_token = auth.create_refresh_token(user_claims=user, audience=token_aud)
    response = client.get('/refresh_token', headers={'Authorization': f'Bearer {refresh_token}'})
    assert response.status_code == 200
    assert response.json() == '1'  # Subject is converted to string


@pytest.mark.parametrize('token_aud', ['bar', ['bar'], ['bar', 'baz']])
def test_invalid_aud_and_missing_aud(client, token_aud):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret-key', authjwt_token_location='headers', authjwt_decode_audience='foo'))

    auth = JWTHarmony()

    user = SimpleUser(id='1')
    access_token = auth.create_access_token(user_claims=user, audience=token_aud)
    response = client.get('/protected', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': "Audience doesn't match"}

    refresh_token = auth.create_refresh_token(user_claims=user)
    response = client.get('/refresh_token', headers={'Authorization': f'Bearer {refresh_token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Token is missing the "aud" claim'}


def test_invalid_decode_algorithms(client):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(
        SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret', authjwt_token_location='headers', authjwt_decode_algorithms=['HS384', 'RS256'])
    )

    auth = JWTHarmony()
    user = SimpleUser(id='1')
    token = auth.create_access_token(user_claims=user)
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'The specified alg value is not allowed'}


@pytest.mark.skipif(not has_crypto, reason='cryptography not installed')
def test_valid_asymmetric_algorithms(client):
    # Reset configuration
    JWTHarmony._config = None

    # Create HS256 token first
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret', authjwt_token_location='headers'))

    auth_hs = JWTHarmony()
    user = SimpleUser(id='1')
    hs256_token = auth_hs.create_access_token(user_claims=user)

    DIR = os.path.abspath(os.path.dirname(__file__))
    private_txt = os.path.join(DIR, 'private_key.txt')
    public_txt = os.path.join(DIR, 'public_key.txt')

    with open(private_txt) as f:
        PRIVATE_KEY = f.read().strip()

    with open(public_txt) as f:
        PUBLIC_KEY = f.read().strip()

    # Reset and configure for RS256
    JWTHarmony._config = None

    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            authjwt_algorithm='RS256',
            authjwt_secret_key='secret',
            authjwt_private_key=PRIVATE_KEY,
            authjwt_public_key=PUBLIC_KEY,
            authjwt_token_location='headers',
        ),
    )

    auth_rs = JWTHarmony()
    rs256_token = auth_rs.create_access_token(user_claims=user)

    response = client.get('/protected', headers={'Authorization': f'Bearer {hs256_token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'The specified alg value is not allowed'}

    response = client.get('/protected', headers={'Authorization': f'Bearer {rs256_token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}


@pytest.mark.skipif(not has_crypto, reason='cryptography not installed')
def test_invalid_asymmetric_algorithms(client):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_algorithm='RS256', authjwt_token_location='headers'))

    auth = JWTHarmony()
    with pytest.raises(RuntimeError, match=r'authjwt_private_key'):
        user = SimpleUser(id='1')
        auth.create_access_token(user_claims=user)

    DIR = os.path.abspath(os.path.dirname(__file__))
    private_txt = os.path.join(DIR, 'private_key.txt')

    with open(private_txt) as f:
        PRIVATE_KEY = f.read().strip()

    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_algorithm='RS256', authjwt_private_key=PRIVATE_KEY, authjwt_token_location='headers'))

    auth2 = JWTHarmony()
    user = SimpleUser(id='1')
    token = auth2.create_access_token(user_claims=user)
    with pytest.raises(RuntimeError, match=r'authjwt_public_key'):
        client.get('/protected', headers={'Authorization': f'Bearer {token}'})
