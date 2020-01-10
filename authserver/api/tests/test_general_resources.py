"""
This module implements the general namespace resources test suite.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.1.0"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

import json

from flask_jwt_extended import decode_token
from sqlalchemy.orm import Session


def create_test_user(app_db_mgr, auth_db_mgr, i=0, enabled=False, is_admin=False):
    user_data = app_db_mgr.insert_user("test"+str(i), "Test User", "test"+str(i)+"@test.com")
    authorization_data = auth_db_mgr.insert_user(user_data.id, user_data.email, "1234",
                                                 enabled=enabled, is_admin=is_admin)

    return user_data, authorization_data


def login_user(http_client, email, password):
    r = http_client.post("api/users/login", json={"email": email, "password": password})
    assert r.status_code == 200

    access_token = r.json.get('access_token')
    assert access_token is not None
    refresh_token = r.json.get('refresh_token')
    assert refresh_token is not None

    return access_token, refresh_token


def get_printer(app_db_mgr, auth_db_mgr):
    printer_data = app_db_mgr.get_printers(id=1)
    authorization_data = auth_db_mgr.get_printers(id=1)
    auth_db_mgr.update_printer(authorization_data, printerKey="1234")

    return printer_data, authorization_data


def login_printer(http_client, serial_number, key):
    r = http_client.post("api/printers/login", json={"serial_number": serial_number, "key": key})
    assert r.status_code == 200

    access_token = r.json.get('access_token')
    assert access_token is not None
    refresh_token = r.json.get('refresh_token')
    assert refresh_token is not None

    return access_token, refresh_token


def detach_from_session(db_object):
    object_session = Session.object_session(db_object)
    object_session.expunge(db_object)


def test_check_access_token(app_db_mgr, auth_db_mgr, http_client):
    normal_user, normal_user_auth = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email

    normal_user_access_token, normal_user_refresh_token = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_refresh_token}

    _, printer = get_printer(app_db_mgr, auth_db_mgr)

    printer_access_token, printer_refresh_token = login_printer(http_client, printer.serialNumber, "1234")
    printer_authorization_header = {"Authorization": "Bearer " + printer_access_token}

    r = http_client.post("api/general/check_access_token", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.post("api/general/check_access_token", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.post("api/general/check_access_token", headers=normal_user_authorization_header)
    assert r.status_code == 422
    assert r.json == {'message': 'Only access tokens are allowed'}

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    r = http_client.post("api/general/check_access_token", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert "X-Identity" in r.headers.keys()
    assert json.loads(r.headers.get("X-Identity")) == decode_token(normal_user_access_token)["sub"]

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_refresh_token}

    r = http_client.post("api/users/logout", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'User logged out.'}

    r = http_client.post("api/general/check_access_token", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Valid access token.'}
    assert "X-Identity" in r.headers.keys()
    assert json.loads(r.headers.get("X-Identity")) == decode_token(printer_access_token)["sub"]

    printer_authorization_header = {"Authorization": "Bearer " + printer_refresh_token}

    r = http_client.post("api/printers/logout", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Printer logged out.'}

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    r = http_client.post("api/general/check_access_token", headers=normal_user_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}

    printer_authorization_header = {"Authorization": "Bearer " + printer_access_token}

    r = http_client.post("api/general/check_access_token", headers=printer_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}


def test_printer_check_refresh_token(app_db_mgr, auth_db_mgr, http_client):
    normal_user, normal_user_auth = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email

    normal_user_access_token, normal_user_refresh_token = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    _, printer = get_printer(app_db_mgr, auth_db_mgr)

    printer_access_token, printer_refresh_token = login_printer(http_client, printer.serialNumber, "1234")
    printer_authorization_header = {"Authorization": "Bearer " + printer_refresh_token}

    r = http_client.post("api/general/check_refresh_token", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.post("api/general/check_refresh_token", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.post("api/general/check_refresh_token", headers=normal_user_authorization_header)
    assert r.status_code == 422
    assert r.json == {'message': 'Only refresh tokens are allowed'}

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_refresh_token}

    r = http_client.post("api/general/check_refresh_token", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Valid refresh token.'}

    r = http_client.post("api/users/logout", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'User logged out.'}

    r = http_client.post("api/general/check_refresh_token", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Valid refresh token.'}

    r = http_client.post("api/printers/logout", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Printer logged out.'}

    r = http_client.post("api/general/check_refresh_token", headers=normal_user_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}

    r = http_client.post("api/general/check_refresh_token", headers=printer_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}
