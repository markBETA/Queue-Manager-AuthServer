import datetime
import os

import pytest

from authserver import create_app
from authserver.database import db as _db
from authserver.database import db_mgr

TEST_DB = 'test.db'
TEST_DB_PATH = "{}".format(TEST_DB)
TEST_DB_URI = 'sqlite:///' + TEST_DB_PATH


@pytest.fixture(scope='session')
def app(request):
    """Session-wide test `Flask` application."""
    settings_override = dict(
        DEBUG=int(os.getenv('DEBUG', 0)),

        SECRET_KEY=os.getenv('SECRET_KEY', 'my_secret_key'),

        SQLALCHEMY_DATABASE_URI=TEST_DB_URI,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ECHO=False,

        RESTPLUS_VALIDATE=True,

        REDIS_SERVER_HOST='localhost',
        REDIS_SERVER_PORT=6379,
        TOKEN_BLACKLIST_REDIS_DB=10,

        JWT_ACCESS_TOKEN_EXPIRES=datetime.timedelta(minutes=30),
        JWT_REFRESH_TOKEN_EXPIRES=datetime.timedelta(days=30),
    )
    app = create_app(__name__, settings_override)

    # Establish an application context before running the tests.
    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return app


@pytest.fixture(scope='session')
def db(app, request):
    """Session-wide test database."""
    if os.path.exists(TEST_DB_PATH):
        os.unlink(TEST_DB_PATH)

    def teardown():
        _db.drop_all()
        if os.path.exists(TEST_DB_PATH):
            os.unlink(TEST_DB_PATH)

    _db.app = app
    _db.create_all()

    request.addfinalizer(teardown)
    return _db


@pytest.fixture(scope='function')
def session(db, request):
    """Creates a new database session for a test."""
    connection = db.engine.connect()
    transaction = connection.begin()

    options = dict(bind=connection, binds={})
    session = db.create_scoped_session(options=options)

    db.session = session

    def teardown():
        transaction.rollback()
        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session


@pytest.fixture(scope='function')
def db_manager(session):
    """Creates a new database DBManager instance for a test."""
    db_mgr.update_session(session)
    db_mgr.init_static_values()

    return db_mgr


@pytest.fixture(scope='function')
def jwt_blacklist_manager(app, request, db_manager):
    from authserver.blacklist_manager import jwt_blacklist_manager

    jwt_blacklist_manager.redis_store.flushdb()

    def teardown():
        jwt_blacklist_manager.redis_store.flushdb()

    request.addfinalizer(teardown)
    return jwt_blacklist_manager


@pytest.fixture(scope='function')
def http_client(app, session, db_manager):
    db_manager.update_session(session)

    return app.test_client()
