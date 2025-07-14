import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyBare, JWTHarmonyDep, JWTHarmonyFresh, JWTHarmonyOptional, JWTHarmonyRefresh
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from tests.user_models import SimpleUser


@pytest.fixture(scope='function')
def client():
    # Reset configuration
    JWTHarmony._config = None
    JWTHarmony._user_model_class = SimpleUser

    app = FastAPI()

    @app.get('/get-token')
    def get_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        # Create tokens for headers (no CSRF needed)
        user = SimpleUser(id='1')
        access_token = Authorize.create_access_token(user_claims=user, fresh=True)
        refresh_token = Authorize.create_refresh_token(user_claims=user)

        # Set the same tokens in cookies (CSRF will be added automatically)
        Authorize.set_access_cookies(access_token)
        Authorize.set_refresh_cookies(refresh_token)
        return {'access': access_token, 'refresh': refresh_token}

    @app.post('/jwt-optional')
    def jwt_optional(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyOptional)):
        return {'hello': Authorize.get_jwt_subject()}

    @app.post('/jwt-required')
    def jwt_required(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'hello': Authorize.get_jwt_subject()}

    @app.post('/jwt-refresh')
    def jwt_refresh(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyRefresh)):
        return {'hello': Authorize.get_jwt_subject()}

    @app.post('/jwt-fresh')
    def jwt_fresh(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyFresh)):
        return {'hello': Authorize.get_jwt_subject()}

    client = TestClient(app)
    return client


# Test multiple token locations - working with current architecture
@pytest.mark.parametrize('url', ['/jwt-optional', '/jwt-required', '/jwt-refresh', '/jwt-fresh'])
def test_get_subject_through_cookie_or_headers(url, client):
    # Reset configuration
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret', authjwt_token_location=['headers', 'cookies']))

    res = client.get('/get-token')
    access_token = res.json()['access']
    refresh_token = res.json()['refresh']

    access_csrf = res.cookies.get('csrf_access_token')
    refresh_csrf = res.cookies.get('csrf_refresh_token')

    # access through headers
    if url != '/jwt-refresh':
        response = client.post(url, headers={'Authorization': f'Bearer {access_token}'})
    else:
        response = client.post(url, headers={'Authorization': f'Bearer {refresh_token}'})

    assert response.status_code == 200
    assert response.json() == {'hello': '1'}

    # access through cookies
    if url != '/jwt-refresh':
        response = client.post(url, headers={'X-CSRF-Token': access_csrf})
    else:
        response = client.post(url, headers={'X-CSRF-Token': refresh_csrf})

    assert response.status_code == 200
    assert response.json() == {'hello': '1'}

    # Reset configuration
    JWTHarmony._config = None
