import os

import pytest
from sqlalchemy.orm import close_all_sessions

try:
    from ... import create_app
except ImportError:
    from .... import create_app
from ..definitions import bind_key
from .. import db as _db
from .. import db_mgr

TESTDB = 'test.db'
TEST_DB_PATH = "{}".format(TESTDB)
TEST_DATABASE_URI = 'sqlite:///' + TEST_DB_PATH

os.chdir(os.path.dirname(__file__))


@pytest.fixture(scope='session')
def app(request):
    """Session-wide test `Flask` application."""
    settings_override = {
        'TESTING': True,
        'SQLALCHEMY_BINDS': {bind_key: 'postgresql+psycopg2://postgres:dev@postgres.dev.server/auth_test'},
        'SQLALCHEMY_TRACK_MODIFICATIONS': True,
        'TEST_INPUTS_PATH': 'input',
        'SECRET_KEY': os.getenv('SECRET_KEY', 'my_secret_key')
    }
    enabled_modules = {
        "auth-database"
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
def db_manager(session):
    """Creates a new app_database DBManager instance for a test."""
    db_mgr.update_session(session)

    return db_mgr
