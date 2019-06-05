import datetime
import os

import pytest
from sqlalchemy.orm import close_all_sessions

from ... import create_app
from ...database import app_db_mgr as _app_db_mgr, auth_db_mgr as _auth_db_mgr
from ...database import db as _db

TEST_DB = 'test.db'
TEST_DB_PATH = "{}".format(TEST_DB)
TEST_DB_URI = 'sqlite:///' + TEST_DB_PATH

os.chdir(os.path.dirname(__file__))


@pytest.fixture(scope='session')
def app(request):
    """Session-wide test `Flask` application."""
    settings_override = dict(
        DEBUG=int(os.getenv('DEBUG', 0)),

        SECRET_KEY=os.getenv('SECRET_KEY', 'my_secret_key'),

        SQLALCHEMY_BINDS={
            'app': 'postgresql+psycopg2://postgres:dev@postgres.dev.server/app_test',
            'auth': 'postgresql+psycopg2://postgres:dev@postgres.dev.server/auth_test'
        },
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ECHO=False,

        REDIS_SERVER_HOST='redis.dev.server',
        REDIS_SERVER_PORT=6379,
        TOKEN_BLACKLIST_REDIS_DB=10,

        JWT_ACCESS_TOKEN_EXPIRES=datetime.timedelta(minutes=30),
        JWT_REFRESH_TOKEN_EXPIRES=datetime.timedelta(days=30),
        JWT_BLACKLIST_ENABLED=True,
        JWT_BLACKLIST_TOKEN_CHECKS=['access', 'refresh'],
        JWT_ERROR_MESSAGE_KEY="message",
        JWT_IDENTITY_CLAIM="sub",
    )
    enabled_modules = {
        "error-handlers",
        "auth-database",
        "app-database",
        "blacklist-manager",
        "api"
    }
    app = create_app(__name__, settings_override, enabled_modules=enabled_modules)

    # Establish an application context before running the tests.
    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return app


@pytest.fixture(scope='function')
def db(app, request):
    """Session-wide test app_database."""
    if os.path.exists(TEST_DB_PATH):
        os.unlink(TEST_DB_PATH)

    def teardown():
        if os.path.exists(TEST_DB_PATH):
            os.unlink(TEST_DB_PATH)

    _db.drop_all()
    _db.create_all()
    _db.session.expunge_all()
    _db.session.remove()

    request.addfinalizer(teardown)
    return _db


@pytest.fixture(scope='function')
def session(db, request):
    """Creates a new app_database session for a test."""
    db.session = db.create_scoped_session()

    def teardown():
        db.session.expunge_all()
        close_all_sessions()

    request.addfinalizer(teardown)
    return db.session


@pytest.fixture(scope='function')
def app_db_mgr(session):
    """Creates a new app_database DBManager instance for a test."""
    _app_db_mgr.update_session(session)

    return _app_db_mgr


@pytest.fixture(scope='function')
def auth_db_mgr(session):
    """Creates a new app_database DBManager instance for a test."""
    _auth_db_mgr.update_session(session)

    return _auth_db_mgr


@pytest.fixture(scope='function')
def jwt_blacklist_manager(app, request, db_manager):
    from authserver.blacklist_manager import jwt_blacklist_manager

    jwt_blacklist_manager.redis_store.flushdb()

    def teardown():
        jwt_blacklist_manager.redis_store.flushdb()

    request.addfinalizer(teardown)
    return jwt_blacklist_manager


@pytest.fixture(scope='function')
def http_client(app, app_db_mgr, auth_db_mgr):
    # app_db_mgr.update_session(session)
    # auth_db_mgr.update_session(session)

    return app.test_client()
