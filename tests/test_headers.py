import pytest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyDep, JWTHarmonyRefresh
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from fastapi_jwt_harmony.exceptions import JWTHarmonyException
from tests.user_models import SimpleUser


@pytest.fixture(scope='function')
def client():
    # Reset configuration for each test
    JWTHarmony._config = None

    # Set default configuration for header-based auth
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_token_location='headers'))

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def authjwt_exception_handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/protected')
    def protected(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'hello': 'world'}

    @app.get('/get_headers_access')
    def get_headers_access(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return Authorize.get_unverified_jwt_headers()

    @app.get('/get_headers_refresh')
    def get_headers_refresh(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyRefresh)):
        return Authorize.get_unverified_jwt_headers()

    client = TestClient(app)
    return client


def test_header_without_jwt(client):
    response = client.get('/protected', headers={'Authorization': 'Bearer'})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    response = client.get('/protected', headers={'Authorization': 'Bearer '})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'Bearer <JWT>'"}


def test_header_without_bearer(client):
    response = client.get('/protected', headers={'Authorization': 'Test asd'})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    response = client.get('/protected', headers={'Authorization': 'Test '})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'Bearer <JWT>'"}


def test_header_invalid_jwt(client):
    response = client.get('/protected', headers={'Authorization': 'Bearer asd'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Not enough segments'}


def test_valid_header(client, authorize_fixture):
    # Reset and reload configuration for headers
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_token_location='headers'))

    user = SimpleUser(id='test')
    token = authorize_fixture.create_access_token(user_claims=user)
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}


def test_jwt_custom_headers(authorize_fixture):
    user1 = SimpleUser(id='1')
    user2 = SimpleUser(id='2')
    access_token = authorize_fixture.create_access_token(user_claims=user1, headers={'access': 'bar'})
    refresh_token = authorize_fixture.create_refresh_token(user_claims=user2, headers={'refresh': 'foo'})

    assert authorize_fixture.get_unverified_jwt_headers(access_token)['access'] == 'bar'
    assert authorize_fixture.get_unverified_jwt_headers(refresh_token)['refresh'] == 'foo'


def test_get_jwt_headers_from_request(client, authorize_fixture):
    # Reset and reload configuration for headers
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_token_location='headers'))

    user1 = SimpleUser(id='1')
    user2 = SimpleUser(id='2')
    access_token = authorize_fixture.create_access_token(user_claims=user1, headers={'access': 'bar'})
    refresh_token = authorize_fixture.create_refresh_token(user_claims=user2, headers={'refresh': 'foo'})

    response = client.get('/get_headers_access', headers={'Authorization': f'Bearer {access_token}'})
    assert response.json()['access'] == 'bar'

    response = client.get('/get_headers_refresh', headers={'Authorization': f'Bearer {refresh_token}'})
    assert response.json()['refresh'] == 'foo'


def test_custom_header_name(authorize_fixture):
    # Reset configuration
    JWTHarmony._config = None
    JWTHarmony._user_model_class = SimpleUser

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_header_name='Foo', authjwt_token_location='headers'))

    # Create new app with custom config
    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def authjwt_exception_handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/protected')
    def protected(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'hello': 'world'}

    client = TestClient(app)

    user = SimpleUser(id='1')
    token = authorize_fixture.create_access_token(user_claims=user)
    # Insure 'default' headers no longer work
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Missing Foo Header'}

    # Insure new headers do work
    response = client.get('/protected', headers={'Foo': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}

    # Invalid headers
    response = client.get('/protected', headers={'Foo': 'Bearer test test'})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Foo header. Expected value 'Bearer <JWT>'"}

    # Reset header name to default
    JWTHarmony._config = None


def test_custom_header_type(authorize_fixture):
    # Reset configuration
    JWTHarmony._config = None
    JWTHarmony._user_model_class = SimpleUser

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_header_type='JWT', authjwt_token_location='headers'))

    # Define dependency after config is set
    def local_auth_jwt_dependency(request: Request = None, response: Response = None):
        return JWTHarmony[SimpleUser](req=request, res=response)

    # Create new app with JWT header type
    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def authjwt_exception_handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/protected')
    def protected(Authorize: JWTHarmony[SimpleUser] = Depends(local_auth_jwt_dependency)):
        return {'hello': 'world'}

    client = TestClient(app)

    user = SimpleUser(id='1')
    token = authorize_fixture.create_access_token(user_claims=user)
    # Insure 'default' headers no longer work
    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'JWT <JWT>'"}
    # Insure new headers do work
    response = client.get('/protected', headers={'Authorization': f'JWT {token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}

    # Reset configuration
    JWTHarmony._config = None
