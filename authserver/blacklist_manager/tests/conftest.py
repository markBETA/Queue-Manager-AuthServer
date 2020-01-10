import os
import pytest

from ... import create_app

TEST_DB = 'test.db'
TEST_DB_PATH = "{}".format(TEST_DB)
TEST_DB_URI = 'sqlite:///' + TEST_DB_PATH

os.chdir(os.path.dirname(__file__))


@pytest.fixture(scope='session')
def app(request):
    """Session-wide test `Flask` application."""
    enabled_modules = {
        "blacklist-manager"
    }
    app = create_app(__name__, testing=True, enabled_modules=enabled_modules)

    # Establish an application context before running the tests.
    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return app


@pytest.fixture(scope="session")
def jwt_manager(app):
    from flask_jwt_extended import JWTManager
    return JWTManager(app)


@pytest.fixture(scope='function')
def jwt_blacklist_manager(app, request):
    from ...blacklist_manager import jwt_blacklist_manager

    jwt_blacklist_manager.redis_store.flushdb()

    def teardown():
        jwt_blacklist_manager.redis_store.flushdb()

    request.addfinalizer(teardown)
    return jwt_blacklist_manager
