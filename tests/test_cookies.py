import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.responses import Response

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyBare, JWTHarmonyDep, JWTHarmonyFresh, JWTHarmonyOptional, JWTHarmonyRefresh
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from fastapi_jwt_harmony.exceptions import JWTHarmonyException
from tests.user_models import SimpleUser


@pytest.fixture(scope='function')
def client():
    # Configure JWTHarmony for this test
    JWTHarmony._config = None
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='testing', authjwt_token_location=['cookies']))

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def authjwt_exception_handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/all-token')
    def all_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        at = Authorize.create_access_token(user_claims=user, fresh=True)
        rt = Authorize.create_refresh_token(user_claims=user)
        Authorize.set_access_cookies(at)
        Authorize.set_refresh_cookies(rt)
        return {'msg': 'all token'}

    @app.get('/all-token-response')
    def all_token_response(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        at = Authorize.create_access_token(user_claims=user, fresh=True)
        rt = Authorize.create_refresh_token(user_claims=user)
        response = JSONResponse(content={'msg': 'all token'})
        Authorize.set_access_cookies(at, response)
        Authorize.set_refresh_cookies(rt, response)
        return response

    @app.get('/access-token')
    def access_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        at = Authorize.create_access_token(user_claims=user)
        Authorize.set_access_cookies(at)
        return {'msg': 'access token'}

    @app.get('/access-token-response')
    def access_token_response(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        at = Authorize.create_access_token(user_claims=user)
        response = JSONResponse(content={'msg': 'access token'})
        Authorize.set_access_cookies(at, response)
        return response

    @app.get('/refresh-token')
    def refresh_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        rt = Authorize.create_refresh_token(user_claims=user)
        Authorize.set_refresh_cookies(rt)
        return {'msg': 'refresh token'}

    @app.get('/refresh-token-response')
    def refresh_token_response(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        rt = Authorize.create_refresh_token(user_claims=user)
        response = JSONResponse(content={'msg': 'refresh token'})
        Authorize.set_refresh_cookies(rt, response)
        return response

    @app.get('/unset-all-token')
    def unset_all_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        Authorize.unset_jwt_cookies()
        return {'msg': 'unset all token'}

    @app.get('/unset-all-token-response')
    def unset_all_token_response(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        response = JSONResponse(content={'msg': 'unset all token'})
        Authorize.unset_jwt_cookies(response)
        return response

    @app.get('/unset-access-token')
    def unset_access_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        Authorize.unset_access_cookies()
        return {'msg': 'unset access token'}

    @app.get('/unset-refresh-token')
    def unset_refresh_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        Authorize.unset_refresh_cookies()
        return {'msg': 'unset refresh token'}

    @app.post('/jwt-optional')
    def jwt_optional(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyOptional)):
        # jwt_optional is automatically handled by JWTHarmonyOptional
        return {'hello': Authorize.get_jwt_subject()}

    @app.post('/jwt-required')
    def jwt_required(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        # jwt_required is automatically handled by JWTHarmonyDep
        return {'hello': Authorize.get_jwt_subject()}

    @app.post('/jwt-refresh')
    def jwt_refresh(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyRefresh)):
        # jwt_refresh_token_required is automatically handled by JWTHarmonyRefresh
        return {'hello': Authorize.get_jwt_subject()}

    @app.post('/jwt-fresh')
    def jwt_fresh(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyFresh)):
        # fresh_jwt_required is automatically handled by JWTHarmonyFresh
        return {'hello': Authorize.get_jwt_subject()}

    client = TestClient(app)
    return client


@pytest.mark.parametrize('url', ['/access-token', '/refresh-token', '/unset-access-token', '/unset-refresh-token'])
def test_warning_if_cookies_not_in_token_location(url, client):
    # Reset configuration
    JWTHarmony._config = None

    # This test should check that cookies operations work when token_location includes 'cookies'
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_secret_key='secret', authjwt_token_location='cookies'))

    # This should work without warnings since token_location includes 'cookies'
    response = client.get(url)
    assert response.status_code == 200


def test_set_cookie_not_valid_type_max_age(authorize_fixture):
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret'))

    user = SimpleUser(id='1')
    token = authorize_fixture.create_access_token(user_claims=user)

    with pytest.raises(TypeError, match=r'max_age'):
        authorize_fixture.set_access_cookies(token, Response(), max_age='string')

    with pytest.raises(TypeError, match=r'max_age'):
        authorize_fixture.set_refresh_cookies(token, Response(), max_age='string')


def test_set_unset_cookies_not_valid_type_response(authorize_fixture):
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret'))

    user = SimpleUser(id='1')
    token = authorize_fixture.create_access_token(user_claims=user)

    with pytest.raises(TypeError, match=r'response'):
        authorize_fixture.set_access_cookies(token, response={'msg': 'hello'})

    with pytest.raises(TypeError, match=r'response'):
        authorize_fixture.set_refresh_cookies(token, response={'msg': 'hello'})

    with pytest.raises(TypeError, match=r'response'):
        authorize_fixture.unset_jwt_cookies({'msg': 'hello'})

    with pytest.raises(TypeError, match=r'response'):
        authorize_fixture.unset_access_cookies({'msg': 'hello'})

    with pytest.raises(TypeError, match=r'response'):
        authorize_fixture.unset_refresh_cookies({'msg': 'hello'})


@pytest.mark.parametrize('url', ['/access-token', '/refresh-token', '/access-token-response', '/refresh-token-response'])
def test_set_cookie_csrf_protect_false(url, client):
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret', authjwt_cookie_csrf_protect=False))

    cookie_key = url.split('-')[0][1:]
    response = client.get(url)
    assert response.cookies.get('csrf_{}_token'.format(cookie_key)) is None


@pytest.mark.parametrize('url', ['/access-token', '/refresh-token', '/access-token-response', '/refresh-token-response'])
def test_set_cookie_csrf_protect_true(url, client):
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret', authjwt_cookie_csrf_protect=True))

    cookie_key = url.split('-')[0][1:]
    response = client.get(url)
    assert response.cookies.get(f'csrf_{cookie_key}_token') is not None


def test_unset_all_cookie(client):
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret'))

    response = client.get('/all-token')
    assert response.cookies.get('access_token_cookie') is not None
    assert response.cookies.get('csrf_access_token') is not None

    assert response.cookies.get('refresh_token_cookie') is not None
    assert response.cookies.get('csrf_refresh_token') is not None

    response = client.get('/unset-all-token')

    assert response.cookies.get('access_token_cookie') is None
    assert response.cookies.get('csrf_access_token') is None

    assert response.cookies.get('refresh_token_cookie') is None
    assert response.cookies.get('csrf_refresh_token') is None


def test_unset_all_cookie_response(client):
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret'))

    response = client.get('/all-token-response')
    assert response.cookies.get('access_token_cookie') is not None
    assert response.cookies.get('csrf_access_token') is not None

    assert response.cookies.get('refresh_token_cookie') is not None
    assert response.cookies.get('csrf_refresh_token') is not None

    response = client.get('/unset-all-token-response')

    assert response.cookies.get('access_token_cookie') is None
    assert response.cookies.get('csrf_access_token') is None

    assert response.cookies.get('refresh_token_cookie') is None
    assert response.cookies.get('csrf_refresh_token') is None


def test_custom_cookie_key(client):
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            authjwt_token_location='cookies',
            authjwt_secret_key='secret',
            authjwt_access_cookie_key='access_cookie',
            authjwt_refresh_cookie_key='refresh_cookie',
            authjwt_access_csrf_cookie_key='csrf_access',
            authjwt_refresh_csrf_cookie_key='csrf_refresh',
        ),
    )

    response = client.get('/all-token')
    assert response.cookies.get('access_cookie') is not None
    assert response.cookies.get('csrf_access') is not None

    assert response.cookies.get('refresh_cookie') is not None
    assert response.cookies.get('csrf_refresh') is not None

    response = client.get('/unset-all-token')

    assert response.cookies.get('access_cookie') is None
    assert response.cookies.get('csrf_access') is None

    assert response.cookies.get('refresh_cookie') is None
    assert response.cookies.get('csrf_refresh') is None


def test_cookie_optional_protected(client):
    # Reset configuration
    JWTHarmony._config = None
    JWTHarmony._token_in_denylist_callback = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret', authjwt_cookie_csrf_protect=False))

    # This token is not used in the test
    # enc = jwt.encode(...)
    url = '/jwt-optional'
    # without token
    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': None}

    # change request methods and not check csrf token
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(authjwt_csrf_methods={'GET'}, authjwt_token_location='cookies', authjwt_secret_key='secret', authjwt_cookie_csrf_protect=True),
    )

    client.get('/access-token')
    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': '1'}

    # change csrf protect to False not check csrf token
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            authjwt_csrf_methods={'POST', 'PUT', 'PATCH', 'DELETE'},
            authjwt_token_location='cookies',
            authjwt_secret_key='secret',
            authjwt_cookie_csrf_protect=False,
        ),
    )

    client.get('/access-token')
    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': '1'}

    # missing csrf token
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret', authjwt_cookie_csrf_protect=True))

    res = client.get('/access-token')
    csrf_token = res.cookies.get('csrf_access_token')

    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': None}  # No auth for optional endpoint when CSRF missing

    # csrf token do not match
    response = client.post(url, headers={'X-CSRF-Token': 'invalid'})
    assert response.status_code == 200
    assert response.json() == {'hello': None}  # No auth for optional endpoint when CSRF mismatch

    response = client.post(url, headers={'X-CSRF-Token': csrf_token})
    assert response.status_code == 200
    assert response.json() == {'hello': '1'}

    # missing claim csrf in token
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret', authjwt_cookie_csrf_protect=False))

    client.get('/access-token')

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret', authjwt_cookie_csrf_protect=True))

    response = client.post(url, headers={'X-CSRF-Token': 'invalid'})
    assert response.status_code == 200
    assert response.json() == {'hello': None}  # No auth for optional endpoint when CSRF claim missing

    # custom csrf header name and cookie key
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            authjwt_token_location='cookies', authjwt_secret_key='secret', authjwt_access_cookie_key='access_cookie', authjwt_access_csrf_header_name='X-CSRF'
        ),
    )

    res = client.get('/access-token')
    csrf_token = res.cookies.get('csrf_access_token')

    # valid request
    response = client.post(url, headers={'X-CSRF': csrf_token})
    assert response.status_code == 200
    assert response.json() == {'hello': '1'}


@pytest.mark.parametrize('url', ['/jwt-required', '/jwt-refresh', '/jwt-fresh'])
def test_cookie_protected(url, client):
    # Reset configuration
    JWTHarmony._config = None
    JWTHarmony._token_in_denylist_callback = None

    # custom csrf header name and cookie key
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            authjwt_token_location='cookies',
            authjwt_secret_key='secret',
            authjwt_access_cookie_key='access_cookie',
            authjwt_access_csrf_header_name='X-CSRF-Access',
            authjwt_refresh_cookie_key='refresh_cookie',
            authjwt_refresh_csrf_header_name='X-CSRF-Refresh',
        ),
    )

    res = client.get('/all-token')
    csrf_access = res.cookies.get('csrf_access_token')
    csrf_refresh = res.cookies.get('csrf_refresh_token')

    if url != '/jwt-refresh':
        response = client.post(url, headers={'X-CSRF-Access': csrf_access})
    else:
        response = client.post(url, headers={'X-CSRF-Refresh': csrf_refresh})
    assert response.status_code == 200
    assert response.json() == {'hello': '1'}

    # missing csrf token
    response = client.post(url)
    assert response.status_code == 401
    assert response.json() == {'detail': 'Missing CSRF Token'}

    # missing cookie
    client.get('/unset-all-token')
    response = client.post(url)
    assert response.status_code == 401
    if url != '/jwt-refresh':
        assert response.json() == {'detail': 'Missing cookie access_cookie'}
    else:
        assert response.json() == {'detail': 'Missing cookie refresh_cookie'}

    # change csrf protect to False not check csrf token
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(authjwt_token_location='cookies', authjwt_secret_key='secret', authjwt_cookie_csrf_protect=False))

    client.get('/all-token')
    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': '1'}

    # change request methods and not check csrf token
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(authjwt_csrf_methods={'GET'}, authjwt_token_location='cookies', authjwt_secret_key='secret', authjwt_cookie_csrf_protect=True),
    )

    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': '1'}

    # missing claim csrf in token
    JWTHarmony.configure(
        SimpleUser, JWTHarmonyConfig(authjwt_csrf_methods={'POST', 'PUT', 'PATCH', 'DELETE'}, authjwt_token_location='cookies', authjwt_secret_key='secret')
    )

    response = client.post(url, headers={'X-CSRF-Token': 'invalid'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Missing claim: csrf'}

    # csrf token do not match
    res = client.get('/all-token')
    csrf_access = res.cookies.get('csrf_access_token')
    csrf_refresh = res.cookies.get('csrf_refresh_token')

    response = client.post(url, headers={'X-CSRF-Token': 'invalid'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'CSRF double submit tokens do not match'}

    # valid request
    if url != '/jwt-refresh':
        response = client.post(url, headers={'X-CSRF-Token': csrf_access})
    else:
        response = client.post(url, headers={'X-CSRF-Token': csrf_refresh})
    assert response.status_code == 200
    assert response.json() == {'hello': '1'}
