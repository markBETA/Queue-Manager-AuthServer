"""
This module implements the job namespace resources test suite.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask_jwt_extended import decode_token
from sqlalchemy.orm import Session


def get_printer(app_db_mgr, auth_db_mgr):
    printer_data = app_db_mgr.get_printers(id=1)
    authorization_data = auth_db_mgr.get_printers(id=1)
    auth_db_mgr.update_printer(authorization_data, printerKey="1234")

    return printer_data, authorization_data


def login_printer(http_client, serial_number, key):
    r = http_client.post("api/printer/login", json={"serial_number": serial_number, "key": key})
    assert r.status_code == 200

    access_token = r.json.get('access_token')
    assert access_token is not None
    refresh_token = r.json.get('refresh_token')
    assert refresh_token is not None

    return access_token, refresh_token


def detach_from_session(db_object):
    object_session = Session.object_session(db_object)
    object_session.expunge(db_object)


def test_get_current_printer(app_db_mgr, auth_db_mgr, http_client):
    _, printer = get_printer(app_db_mgr, auth_db_mgr)
    printer_id = printer.id

    printer_access_token, _ = login_printer(http_client, printer.serialNumber, "1234")
    printer_authorization_header = {"Authorization": "Bearer "+printer_access_token}

    r = http_client.get("api/printer/current")
    print(r.json)
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.get("api/printer/current", headers={"Authorization": "Bearer "})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    authorization_data = auth_db_mgr.get_printers(id=printer_id)

    r = http_client.get("api/printer/current", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {"id": authorization_data.id, "serial_number": authorization_data.serialNumber}


def test_printer_login(app_db_mgr, auth_db_mgr, http_client):
    _, printer = get_printer(app_db_mgr, auth_db_mgr)
    printer_serial_number = printer.serialNumber
    printer_identity = printer.identity

    r = http_client.post("api/printer/login", json={})
    assert r.status_code == 400
    assert r.json == {
        'errors': {
            'key': "'key' is a required property",
            'serial_number': "'serial_number' is a required property"
        },
        'message': 'Input payload validation failed'
    }

    r = http_client.post("api/printer/login", json={"serial_number": printer_serial_number})
    assert r.status_code == 400
    assert r.json == {
        'errors': {
            'key': "'key' is a required property",
        },
        'message': 'Input payload validation failed'
    }

    r = http_client.post("api/printer/login", json={"serial_number": printer_serial_number, "key": True})
    assert r.status_code == 400
    assert r.status_code == 400
    assert r.json == {
        'errors': {
            'key': "True is not of type 'string'"
        },
        'message': 'Input payload validation failed'
    }

    r = http_client.post("api/printer/login", json={"serial_number": "000.00000.0000", "key": "test"})
    assert r.status_code == 401
    assert r.json == {'message': 'There isn\'t any registered printer with this serial number.'}

    r = http_client.post("api/printer/login", json={"serial_number": printer_serial_number, "key": "1234abc"})
    assert r.status_code == 401
    assert r.json == {'message': 'Incorrect printer key.'}

    r = http_client.post("api/printer/login", json={"serial_number": printer_serial_number, "key": "1234"})
    assert r.status_code == 200

    access_token = r.json.get('access_token')
    assert access_token is not None
    refresh_token = r.json.get('refresh_token')
    assert refresh_token is not None

    decoded_access_token = decode_token(access_token)
    decoded_refresh_token = decode_token(refresh_token)

    assert decoded_access_token.get("sub", None) == printer_identity
    assert decoded_refresh_token.get("sub", None) == printer_identity


def test_printer_access_refresh(app_db_mgr, auth_db_mgr, http_client):
    _, printer = get_printer(app_db_mgr, auth_db_mgr)

    printer_access_token, printer_refresh_token = login_printer(http_client, printer.serialNumber, "1234")
    printer_authorization_header = {"Authorization": "Bearer " + printer_access_token}

    r = http_client.post("api/printer/access_refresh", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.post("api/printer/access_refresh", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.post("api/printer/access_refresh", headers=printer_authorization_header)
    assert r.status_code == 422
    assert r.json == {'message': 'Only refresh tokens are allowed'}

    printer_authorization_header = {"Authorization": "Bearer " + printer_refresh_token}

    r = http_client.post("api/printer/access_refresh", headers=printer_authorization_header)
    new_access_token = r.json.get("access_token")
    assert r.status_code == 200
    assert new_access_token is not None

    printer_authorization_header = {"Authorization": "Bearer " + printer_access_token}

    r = http_client.post("api/printer/check_access_token", headers=printer_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}

    printer_authorization_header = {"Authorization": "Bearer " + new_access_token}

    r = http_client.post("api/printer/check_access_token", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Valid access token.'}


def test_printer_logout(app_db_mgr, auth_db_mgr, http_client):
    _, printer = get_printer(app_db_mgr, auth_db_mgr)

    printer_access_token, printer_refresh_token = login_printer(http_client, printer.serialNumber, "1234")
    printer_authorization_header = {"Authorization": "Bearer " + printer_access_token}

    r = http_client.post("api/printer/logout", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.post("api/printer/logout", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.post("api/printer/logout", headers=printer_authorization_header)
    assert r.status_code == 422
    assert r.json == {'message': 'Only refresh tokens are allowed'}

    printer_authorization_header = {"Authorization": "Bearer " + printer_refresh_token}

    r = http_client.post("api/printer/logout", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Printer logged out.'}

    r = http_client.post("api/printer/check_refresh_token", headers=printer_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}

    printer_authorization_header = {"Authorization": "Bearer " + printer_access_token}

    r = http_client.post("api/printer/check_access_token", headers=printer_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}


def test_printer_check_access_token(app_db_mgr, auth_db_mgr, http_client):
    _, printer = get_printer(app_db_mgr, auth_db_mgr)

    printer_access_token, printer_refresh_token = login_printer(http_client, printer.serialNumber, "1234")
    printer_authorization_header = {"Authorization": "Bearer " + printer_refresh_token}

    r = http_client.post("api/printer/check_access_token", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.post("api/printer/check_access_token", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.post("api/printer/check_access_token", headers=printer_authorization_header)
    assert r.status_code == 422
    assert r.json == {'message': 'Only access tokens are allowed'}

    printer_authorization_header = {"Authorization": "Bearer " + printer_access_token}

    r = http_client.post("api/printer/check_access_token", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Valid access token.'}

    printer_authorization_header = {"Authorization": "Bearer " + printer_refresh_token}

    r = http_client.post("api/printer/logout", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Printer logged out.'}

    printer_authorization_header = {"Authorization": "Bearer " + printer_access_token}

    r = http_client.post("api/printer/check_access_token", headers=printer_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}


def test_printer_check_refresh_token(app_db_mgr, auth_db_mgr, http_client):
    _, printer = get_printer(app_db_mgr, auth_db_mgr)

    printer_access_token, printer_refresh_token = login_printer(http_client, printer.serialNumber, "1234")
    printer_authorization_header = {"Authorization": "Bearer " + printer_access_token}

    r = http_client.post("api/printer/check_refresh_token", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.post("api/printer/check_refresh_token", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.post("api/printer/check_refresh_token", headers=printer_authorization_header)
    assert r.status_code == 422
    assert r.json == {'message': 'Only refresh tokens are allowed'}

    printer_authorization_header = {"Authorization": "Bearer " + printer_refresh_token}

    r = http_client.post("api/printer/check_refresh_token", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Valid refresh token.'}

    r = http_client.post("api/printer/logout", headers=printer_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Printer logged out.'}

    r = http_client.post("api/printer/check_refresh_token", headers=printer_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}
