from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyDep, JWTHarmonyFresh, JWTHarmonyOptional, JWTHarmonyRefresh
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from fastapi_jwt_harmony.exceptions import JWTHarmonyException
from tests.user_models import SimpleUser

# setting for denylist token
denylist = set()


def test_denylist_functionality():
    """Test denylist functionality in a single test to maintain state"""
    # Reset configuration and callback
    JWTHarmony._config = None
    JWTHarmony._token_in_denylist_callback = None
    JWTHarmony._user_model_class = SimpleUser
    denylist.clear()

    def check_if_token_in_denylist(decrypted_token):
        jti = decrypted_token['jti']
        return jti in denylist

    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_denylist_enabled=True, authjwt_token_location='headers'),
        denylist_callback=check_if_token_in_denylist,
    )

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def authjwt_exception_handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/jwt-required')
    def jwt_required(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'hello': 'world'}

    @app.get('/jwt-optional')
    def jwt_optional(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyOptional)):
        return {'hello': 'world'}

    @app.get('/jwt-refresh-required')
    def jwt_refresh_required(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyRefresh)):
        return {'hello': 'world'}

    @app.get('/fresh-jwt-required')
    def fresh_jwt_required(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyFresh)):
        return {'hello': 'world'}

    client = TestClient(app)
    auth = JWTHarmony[SimpleUser]()

    # Create tokens
    user = SimpleUser(id='test')
    access_token = auth.create_access_token(user_claims=user, fresh=True)
    refresh_token = auth.create_refresh_token(user_claims=user)

    # Test 1: Non-denylisted access token works
    for url in ['/jwt-required', '/jwt-optional', '/fresh-jwt-required']:
        response = client.get(url, headers={'Authorization': f'Bearer {access_token}'})
        assert response.status_code == 200
        assert response.json() == {'hello': 'world'}

    # Test 2: Non-denylisted refresh token works
    response = client.get('/jwt-refresh-required', headers={'Authorization': f'Bearer {refresh_token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}

    # Add tokens to denylist
    auth._token = access_token
    access_jti = auth.get_jti()
    auth._token = refresh_token
    refresh_jti = auth.get_jti()
    denylist.add(access_jti)
    denylist.add(refresh_jti)

    # Test 3: Denylisted access token is rejected
    for url in ['/jwt-required', '/jwt-optional', '/fresh-jwt-required']:
        response = client.get(url, headers={'Authorization': f'Bearer {access_token}'})
        assert response.status_code == 401
        assert response.json() == {'detail': 'Token has been revoked'}

    # Test 4: Denylisted refresh token is rejected
    response = client.get('/jwt-refresh-required', headers={'Authorization': f'Bearer {refresh_token}'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Token has been revoked'}


def test_denylist_only_checks_configured_token_types():
    """Test that denylist only checks token types configured in authjwt_denylist_token_checks"""
    # Reset configuration and callback
    JWTHarmony._config = None
    JWTHarmony._token_in_denylist_callback = None
    JWTHarmony._user_model_class = SimpleUser
    denylist.clear()

    def check_if_token_in_denylist(decrypted_token):
        jti = decrypted_token['jti']
        return jti in denylist

    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            authjwt_secret_key='testing',
            authjwt_denylist_enabled=True,
            authjwt_denylist_token_checks={'access'},  # Only check access tokens
            authjwt_token_location='headers',
        ),
        denylist_callback=check_if_token_in_denylist,
    )

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def authjwt_exception_handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/jwt-required')
    def jwt_required(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'hello': 'world'}

    @app.get('/jwt-refresh-required')
    def jwt_refresh_required(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyRefresh)):
        return {'hello': 'world'}

    client = TestClient(app)
    auth = JWTHarmony[SimpleUser]()

    # Create tokens
    user = SimpleUser(id='test')
    access_token = auth.create_access_token(user_claims=user)
    refresh_token = auth.create_refresh_token(user_claims=user)

    # Add both tokens to denylist
    auth._token = access_token
    access_jti = auth.get_jti()
    auth._token = refresh_token
    refresh_jti = auth.get_jti()
    denylist.add(access_jti)
    denylist.add(refresh_jti)

    # Access token should be rejected (it's in the check list)
    response = client.get('/jwt-required', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Token has been revoked'}

    # Refresh token should work (not in the check list)
    response = client.get('/jwt-refresh-required', headers={'Authorization': f'Bearer {refresh_token}'})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}
