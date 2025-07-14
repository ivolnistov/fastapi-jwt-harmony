import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyDep, JWTHarmonyFresh, JWTHarmonyOptional, JWTHarmonyRefresh
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from fastapi_jwt_harmony.exceptions import JWTHarmonyException
from tests.user_models import SimpleUser


@pytest.fixture(scope='function')
def client():
    # Reset configuration
    JWTHarmony._config = None
    JWTHarmony._user_model_class = SimpleUser

    # Set default configuration for header-based auth
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_token_location='headers'))

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def authjwt_exception_handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/jwt-required')
    def jwt_required(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'hello': 'world'}

    @app.get('/jwt-optional')
    def jwt_optional(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyOptional)):
        if Authorize.get_jwt_subject():
            return {'hello': 'world'}
        return {'hello': 'anonym'}

    @app.get('/jwt-refresh-required')
    def jwt_refresh_required(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyRefresh)):
        return {'hello': 'world'}

    @app.get('/fresh-jwt-required')
    def fresh_jwt_required(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyFresh)):
        return {'hello': 'world'}

    client = TestClient(app)
    return client


@pytest.mark.parametrize('url', ['/jwt-required', '/jwt-refresh-required', '/fresh-jwt-required'])
def test_missing_header(client, url):
    response = client.get(url)
    assert response.status_code == 401
    assert response.json() == {'detail': 'Missing Authorization Header'}


@pytest.mark.parametrize('url', ['/jwt-required', '/jwt-optional', '/fresh-jwt-required'])
def test_only_access_token_allowed(client, url, authorize_fixture):
    # Ensure config is set to headers
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_token_location='headers'))

    user = SimpleUser(id='test')
    token = authorize_fixture.create_refresh_token(user_claims=user)
    response = client.get(url, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Only access tokens are allowed'}


def test_jwt_required(client, authorize_fixture):
    url = '/jwt-required'
    # Ensure config is set to headers
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_token_location='headers'))

    user = SimpleUser(id='test')
    token = authorize_fixture.create_access_token(user_claims=user)
    response = client.get(url, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}


def test_jwt_optional(client, authorize_fixture):
    url = '/jwt-optional'
    # Ensure config is set to headers
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_token_location='headers'))

    # if header not define return anonym user
    response = client.get(url)
    assert response.status_code == 200
    assert response.json() == {'hello': 'anonym'}

    user = SimpleUser(id='test')
    token = authorize_fixture.create_access_token(user_claims=user)
    response = client.get(url, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}


def test_refresh_required(client, authorize_fixture):
    url = '/jwt-refresh-required'
    # Ensure config is set to headers
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_token_location='headers'))

    # only refresh token allowed
    user = SimpleUser(id='test')
    token = authorize_fixture.create_access_token(user_claims=user)
    response = client.get(url, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Only refresh tokens are allowed'}

    user = SimpleUser(id='test')
    token = authorize_fixture.create_refresh_token(user_claims=user)
    response = client.get(url, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}


def test_fresh_jwt_required(client, authorize_fixture):
    url = '/fresh-jwt-required'
    # Ensure config is set to headers
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_token_location='headers'))

    # only fresh token allowed
    user = SimpleUser(id='test')
    token = authorize_fixture.create_access_token(user_claims=user)
    response = client.get(url, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Fresh token required'}

    token = authorize_fixture.create_access_token(user_claims=user, fresh=True)
    response = client.get(url, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}
