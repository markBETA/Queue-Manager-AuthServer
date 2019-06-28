"""
This module implements the job namespace resources test suite.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.2"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from flask_jwt_extended import decode_token
from flask_restplus import marshal
from sqlalchemy.orm import Session

from ..users.models import (
    user_model
)


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


def detach_from_session(db_object):
    object_session = Session.object_session(db_object)
    object_session.expunge(db_object)


def test_get_users(app_db_mgr, auth_db_mgr, http_client):
    normal_user, _ = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email
    admin_user, _ = create_test_user(app_db_mgr, auth_db_mgr, i=1, enabled=True, is_admin=True)
    admin_user_email = admin_user.email

    normal_user_access_token, _ = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer "+normal_user_access_token}

    admin_user_access_token, _ = login_user(http_client, admin_user_email, "1234")
    admin_user_authorization_header = {"Authorization": "Bearer "+admin_user_access_token}

    r = http_client.get("api/users")
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.get("api/users", headers={"Authorization": "Bearer "})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.get("api/users", headers=normal_user_authorization_header)
    assert r.status_code == 403
    assert r.json == {'message': 'Only users with administrator privileges can list all users.'}

    users_data = []
    users = app_db_mgr.get_users()

    for user in users:
        authorization_data = auth_db_mgr.get_users(id=user.id)
        users_data.append({"user_data": user, "authorization_data": authorization_data})

    r = http_client.get("api/users", headers=admin_user_authorization_header)
    assert r.status_code == 200
    assert r.json == marshal(users_data, user_model)


def test_register_user(app_db_mgr, auth_db_mgr, http_client):
    user_register_data = {
        'username': 'test',
        'fullname': 'Test User',
        'email': 'test@test.com',
        'password': '1234'
    }

    r = http_client.post("api/users", json={})
    assert r.status_code == 400
    assert r.json == {
        'message': 'Input payload validation failed',
        'errors': {
            'email': "'email' is a required property",
            'fullname': "'fullname' is a required property",
            'password': "'password' is a required property",
            'username': "'username' is a required property"
        }
    }

    user_register_data_fail = user_register_data.copy()
    user_register_data_fail["username"] = 1.0

    r = http_client.post("api/users", json=user_register_data_fail)
    assert r.status_code == 400
    assert r.json == {
        'message': 'Input payload validation failed',
        'errors': {
            'username': "1.0 is not of type 'string'"
        }
    }

    user_register_data_fail = user_register_data.copy()
    user_register_data_fail["email"] = "test"

    r = http_client.post("api/users", json=user_register_data_fail)
    assert r.status_code == 400
    assert r.json == {
        'message': 'Input payload validation failed',
        'errors': {
            'email': "Invalid email format"
        }
    }

    r = http_client.post("api/users", json=user_register_data)
    user_data = app_db_mgr.get_users(email=user_register_data["email"])
    authorization_data = auth_db_mgr.get_users(email=user_register_data["email"])
    assert r.status_code == 201
    assert r.json == marshal({"user_data": user_data, "authorization_data": authorization_data}, user_model)

    user_register_data_fail = user_register_data.copy()
    user_register_data_fail["email"] = "test1@test.com"

    r = http_client.post("api/users", json=user_register_data_fail)
    assert r.status_code == 409
    assert r.json == {'message': 'Username already in use'}

    user_register_data_fail = user_register_data.copy()
    user_register_data_fail["username"] = "test1"

    r = http_client.post("api/users", json=user_register_data_fail)
    assert r.status_code == 409
    assert r.json == {'message': 'Email already in use'}


def test_get_current_user(app_db_mgr, auth_db_mgr, http_client):
    normal_user, _ = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email

    normal_user_access_token, _ = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer "+normal_user_access_token}

    r = http_client.get("api/users/current")
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.get("api/users/current", headers={"Authorization": "Bearer "})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    user_data = app_db_mgr.get_users(email=normal_user_email)
    authorization_data = auth_db_mgr.get_users(id=user_data.id)

    r = http_client.get("api/users/current", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == marshal({"user_data": user_data, "authorization_data": authorization_data}, user_model)


def test_edit_current_user(app_db_mgr, auth_db_mgr, http_client):
    normal_user, _ = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_id = normal_user.id
    normal_user_email = normal_user.email

    normal_user_access_token, _ = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer "+normal_user_access_token}

    edit_user_data = {
        'current_password': '1234',
        'username': 'test-edited',
        'fullname': 'Test User Edited',
        'email': 'test-edited@test.com',
        'new_password': '1234abc'
    }

    r = http_client.put("api/users/current", json=edit_user_data)
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.put("api/users/current", headers={"Authorization": "Bearer "}, json=edit_user_data)
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.put("api/users/current", headers=normal_user_authorization_header, json={})
    assert r.status_code == 400
    assert r.json == {
        'message': 'Input payload validation failed',
        'errors': {
            'current_password': "'current_password' is a required property",
        }
    }

    edit_user_data_fail = edit_user_data.copy()
    edit_user_data_fail["email"] = "test"

    r = http_client.put("api/users/current", headers=normal_user_authorization_header, json=edit_user_data_fail)
    assert r.status_code == 400
    assert r.json == {
        'message': 'Input payload validation failed',
        'errors': {
            'email': "Invalid email format"
        }
    }

    edit_user_data_fail = edit_user_data.copy()
    edit_user_data_fail["username"] = 1.0

    r = http_client.put("api/users/current", headers=normal_user_authorization_header, json=edit_user_data_fail)
    assert r.status_code == 400
    assert r.json == {
        'message': 'Input payload validation failed',
        'errors': {
            'username': "1.0 is not of type 'string'"
        }
    }

    edit_user_data_fail = edit_user_data.copy()
    edit_user_data_fail["current_password"] = 'abcd'

    r = http_client.put("api/users/current", headers=normal_user_authorization_header, json=edit_user_data_fail)
    assert r.status_code == 401
    assert r.json == {'message': 'Incorrect current password for this user.'}

    r = http_client.put("api/users/current", headers=normal_user_authorization_header, json=edit_user_data)
    user_data = app_db_mgr.get_users(id=normal_user_id)
    auth_data = auth_db_mgr.get_users(id=normal_user_id)
    assert r.status_code == 200
    assert r.json == {'message': 'User data updated successfully.'}
    assert user_data.username == edit_user_data['username']
    assert user_data.fullname == edit_user_data['fullname']
    assert user_data.email == edit_user_data['email']
    assert auth_data.verify_password(edit_user_data['new_password'])

    edit_user_data["current_password"] = "1234abc"
    edit_user_data_fail = edit_user_data.copy()
    edit_user_data_fail["email"] = "test0@test.com"
    create_test_user(app_db_mgr, auth_db_mgr, enabled=True)

    r = http_client.put("api/users/current", headers=normal_user_authorization_header, json=edit_user_data_fail)
    assert r.status_code == 409
    assert r.json == {'message': 'Email already in use'}

    edit_user_data_fail = edit_user_data.copy()
    edit_user_data_fail["username"] = "test0"

    r = http_client.put("api/users/current", headers=normal_user_authorization_header, json=edit_user_data_fail)
    assert r.status_code == 409
    assert r.json == {'message': 'Username already in use'}

    del edit_user_data_fail["email"]
    r = http_client.put("api/users/current", headers=normal_user_authorization_header, json=edit_user_data)
    user_data = app_db_mgr.get_users(id=normal_user_id)
    auth_data = auth_db_mgr.get_users(id=normal_user_id)
    assert r.status_code == 200
    assert r.json == {'message': 'User data updated successfully.'}
    assert user_data.username == edit_user_data['username']
    assert user_data.fullname == edit_user_data['fullname']
    assert auth_data.verify_password(edit_user_data['new_password'])


def test_get_user(app_db_mgr, auth_db_mgr, http_client):
    normal_user, _ = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email
    normal_user_id = normal_user.id
    admin_user, _ = create_test_user(app_db_mgr, auth_db_mgr, i=1, enabled=True, is_admin=True)
    admin_user_email = admin_user.email

    normal_user_access_token, _ = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer "+normal_user_access_token}

    admin_user_access_token, _ = login_user(http_client, admin_user_email, "1234")
    admin_user_authorization_header = {"Authorization": "Bearer "+admin_user_access_token}

    r = http_client.get("api/users/1")
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.get("api/users/1", headers={"Authorization": "Bearer "})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.get("api/users/1", headers=normal_user_authorization_header)
    assert r.status_code == 403
    assert r.json == {'message': 'You need to be an administrator to see another user data.'}

    user_data = app_db_mgr.get_users(id=normal_user_id)
    authorization_data = auth_db_mgr.get_users(id=user_data.id)

    r = http_client.get("api/users/" + str(normal_user_id), headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == marshal({"user_data": user_data, "authorization_data": authorization_data}, user_model)

    r = http_client.get("api/users/100", headers=admin_user_authorization_header)
    assert r.status_code == 404
    assert r.json == {'message': 'There isn\'t any registered user with this identifier.'}

    user_data = app_db_mgr.get_users(id=normal_user_id)
    authorization_data = auth_db_mgr.get_users(id=user_data.id)

    r = http_client.get("api/users/" + str(normal_user_id), headers=admin_user_authorization_header)
    assert r.status_code == 200
    assert r.json == marshal({"user_data": user_data, "authorization_data": authorization_data}, user_model)


def test_delete_user(app_db_mgr, auth_db_mgr, http_client):
    normal_user, normal_user_auth = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email
    normal_user_id = normal_user.id
    admin_user, _ = create_test_user(app_db_mgr, auth_db_mgr, i=1, enabled=True, is_admin=True)
    admin_user_email = admin_user.email
    admin_user_id = admin_user.id

    normal_user_access_token, _ = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer "+normal_user_access_token}

    admin_user_access_token, _ = login_user(http_client, admin_user_email, "1234")
    admin_user_authorization_header = {"Authorization": "Bearer "+admin_user_access_token}

    r = http_client.delete("api/users/1")
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.delete("api/users/1", headers={"Authorization": "Bearer "})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.delete("api/users/1", headers=normal_user_authorization_header)
    assert r.status_code == 403
    assert r.json == {'message': 'You need to be an administrator to delete another user.'}

    user_data = app_db_mgr.get_users(id=normal_user_id)
    authorization_data = auth_db_mgr.get_users(id=user_data.id)

    r = http_client.delete("api/users/" + str(normal_user_id), headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == marshal({"user_data": user_data, "authorization_data": authorization_data}, user_model)
    assert app_db_mgr.get_users(id=normal_user_id) is None
    assert auth_db_mgr.get_users(id=normal_user_id) is None

    r = http_client.delete("api/users/100", headers=admin_user_authorization_header)
    assert r.status_code == 404
    assert r.json == {'message': 'There isn\'t any registered user with this identifier.'}

    user_data = app_db_mgr.get_users(id=1)
    authorization_data = auth_db_mgr.get_users(id=user_data.id)

    r = http_client.delete("api/users/1", headers=admin_user_authorization_header)
    assert r.status_code == 200
    assert r.json == marshal({"user_data": user_data, "authorization_data": authorization_data}, user_model)
    assert app_db_mgr.get_users(id=1) is None
    assert auth_db_mgr.get_users(id=1) is None

    r = http_client.delete("api/users/" + str(admin_user_id), headers=admin_user_authorization_header)
    assert r.status_code == 403
    assert r.json == {'message': 'At least one admin user is needed.'}


def test_authorize_user(app_db_mgr, auth_db_mgr, http_client):
    normal_user, normal_user_auth = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email
    normal_user_id = normal_user.id
    admin_user, _ = create_test_user(app_db_mgr, auth_db_mgr, i=1, enabled=True, is_admin=True)
    admin_user_email = admin_user.email

    normal_user_access_token, _ = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    admin_user_access_token, _ = login_user(http_client, admin_user_email, "1234")
    admin_user_authorization_header = {"Authorization": "Bearer " + admin_user_access_token}

    r = http_client.put("api/users/1/authorization", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.put("api/users/1/authorization", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.put("api/users/1/authorization", headers=normal_user_authorization_header, json={})
    assert r.status_code == 403
    assert r.json == {'message': 'You need to be an administrator to edit users authorization data.'}

    r = http_client.put("api/users/1/authorization", headers=admin_user_authorization_header, json={})
    assert r.status_code == 200
    assert r.json == {'message': 'User authorization data updated successfully.'}

    r = http_client.put("api/users/1/authorization", headers=admin_user_authorization_header, json={"is_admin": "abc"})
    assert r.status_code == 400
    assert r.json == {
        'message': 'Input payload validation failed',
        'errors': {'is_admin': "'abc' is not of type 'boolean'"}
    }

    r = http_client.put("api/users/"+str(normal_user_id)+"/authorization", headers=admin_user_authorization_header,
                        json={"is_admin": True})
    assert r.status_code == 200
    assert r.json == {'message': 'User authorization data updated successfully.'}

    normal_user = auth_db_mgr.get_users(id=normal_user_id)
    assert normal_user.enabled is True
    assert normal_user.isAdmin is True

    r = http_client.put("api/users/" + str(normal_user_id) + "/authorization", headers=admin_user_authorization_header,
                        json={"enabled": False})
    assert r.status_code == 200
    assert r.json == {'message': 'User authorization data updated successfully.'}

    normal_user = auth_db_mgr.get_users(id=normal_user_id)
    assert normal_user.enabled is False
    assert normal_user.isAdmin is True

    r = http_client.put("api/users/" + str(normal_user_id) + "/authorization", headers=admin_user_authorization_header,
                        json={"enabled": True, "is_admin": False})
    assert r.status_code == 200
    assert r.json == {'message': 'User authorization data updated successfully.'}

    normal_user = auth_db_mgr.get_users(id=normal_user_id)
    assert normal_user.enabled is True
    assert normal_user.isAdmin is False


def test_user_login(app_db_mgr, auth_db_mgr, http_client):
    normal_user, normal_user_auth = create_test_user(app_db_mgr, auth_db_mgr, enabled=False)
    normal_user_email = normal_user.email
    admin_user, admin_user_auth = create_test_user(app_db_mgr, auth_db_mgr, i=1, enabled=True, is_admin=True)
    admin_user_email = admin_user.email
    admin_user_identity = admin_user_auth.identity

    r = http_client.post("api/users/login", json={})
    assert r.status_code == 400
    assert r.json == {
        'errors': {
            'email': "'email' is a required property",
            'password': "'password' is a required property"
        },
        'message': 'Input payload validation failed'
    }

    r = http_client.post("api/users/login", json={"email": normal_user_email})
    assert r.status_code == 400
    assert r.json == {
        'errors': {
            'password': "'password' is a required property"
        },
        'message': 'Input payload validation failed'
    }

    r = http_client.post("api/users/login", json={"email": normal_user_email, "password": True})
    assert r.status_code == 400
    assert r.status_code == 400
    assert r.json == {
        'errors': {
            'password': "True is not of type 'string'"
        },
        'message': 'Input payload validation failed'
    }

    r = http_client.post("api/users/login", json={"email": "test", "password": "test"})
    assert r.status_code == 400
    assert r.json == {
       'message': 'Input payload validation failed',
       'errors': {
           'email': "Invalid email format"
       }
    }

    r = http_client.post("api/users/login", json={"email": "test@test.com", "password": "test"})
    assert r.status_code == 401
    assert r.json == {'message': 'There isn\'t any registered user with this email.'}

    r = http_client.post("api/users/login", json={"email": normal_user_email, "password": "1234"})
    assert r.status_code == 401
    assert r.json == {'message': 'This user is not enabled. Please contact with the administrator to enable it.'}

    r = http_client.post("api/users/login", json={"email": admin_user_email, "password": "1234abc"})
    assert r.status_code == 401
    assert r.json == {'message': 'Incorrect password for this user.'}

    r = http_client.post("api/users/login", json={"email": admin_user_email, "password": "1234"})
    assert r.status_code == 200

    access_token = r.json.get('access_token')
    assert access_token is not None
    refresh_token = r.json.get('refresh_token')
    assert refresh_token is not None

    decoded_access_token = decode_token(access_token)
    decoded_refresh_token = decode_token(refresh_token)

    assert decoded_access_token.get("sub", None) == admin_user_identity
    assert decoded_refresh_token.get("sub", None) == admin_user_identity


def test_user_access_refresh(app_db_mgr, auth_db_mgr, http_client):
    normal_user, normal_user_auth = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email

    normal_user_access_token, normal_user_refresh_token = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    r = http_client.post("api/users/access_refresh", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.post("api/users/access_refresh", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.post("api/users/access_refresh", headers=normal_user_authorization_header)
    assert r.status_code == 422
    assert r.json == {'message': 'Only refresh tokens are allowed'}

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_refresh_token}

    r = http_client.post("api/users/access_refresh", headers=normal_user_authorization_header)
    new_access_token = r.json.get("access_token")
    assert r.status_code == 200
    assert new_access_token is not None

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    r = http_client.post("api/users/check_access_token", headers=normal_user_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}

    normal_user_authorization_header = {"Authorization": "Bearer " + new_access_token}

    r = http_client.post("api/users/check_access_token", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Valid access token.'}


def test_user_logout(app_db_mgr, auth_db_mgr, http_client):
    normal_user, normal_user_auth = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email

    normal_user_access_token, normal_user_refresh_token = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    r = http_client.post("api/users/logout", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.post("api/users/logout", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.post("api/users/logout", headers=normal_user_authorization_header)
    assert r.status_code == 422
    assert r.json == {'message': 'Only refresh tokens are allowed'}

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_refresh_token}

    r = http_client.post("api/users/logout", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'User logged out.'}

    r = http_client.post("api/users/check_refresh_token", headers=normal_user_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    r = http_client.post("api/users/check_access_token", headers=normal_user_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}


def test_user_check_access_token(app_db_mgr, auth_db_mgr, http_client):
    normal_user, normal_user_auth = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email

    normal_user_access_token, normal_user_refresh_token = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_refresh_token}

    r = http_client.post("api/users/check_access_token", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.post("api/users/check_access_token", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.post("api/users/check_access_token", headers=normal_user_authorization_header)
    assert r.status_code == 422
    assert r.json == {'message': 'Only access tokens are allowed'}

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    r = http_client.post("api/users/check_access_token", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Valid access token.'}

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_refresh_token}

    r = http_client.post("api/users/logout", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'User logged out.'}

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    r = http_client.post("api/users/check_access_token", headers=normal_user_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}


def test_user_check_refresh_token(app_db_mgr, auth_db_mgr, http_client):
    normal_user, normal_user_auth = create_test_user(app_db_mgr, auth_db_mgr, enabled=True)
    normal_user_email = normal_user.email

    normal_user_access_token, normal_user_refresh_token = login_user(http_client, normal_user_email, "1234")
    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_access_token}

    r = http_client.post("api/users/check_refresh_token", json={})
    assert r.status_code == 401
    assert r.json == {"message": "Missing Authorization Header"}

    r = http_client.post("api/users/check_refresh_token", headers={"Authorization": "Bearer "}, json={})
    assert r.status_code == 422
    assert r.json == {'message': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    r = http_client.post("api/users/check_refresh_token", headers=normal_user_authorization_header)
    assert r.status_code == 422
    assert r.json == {'message': 'Only refresh tokens are allowed'}

    normal_user_authorization_header = {"Authorization": "Bearer " + normal_user_refresh_token}

    r = http_client.post("api/users/check_refresh_token", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'Valid refresh token.'}

    r = http_client.post("api/users/logout", headers=normal_user_authorization_header)
    assert r.status_code == 200
    assert r.json == {'message': 'User logged out.'}

    r = http_client.post("api/users/check_refresh_token", headers=normal_user_authorization_header)
    assert r.status_code == 401
    assert r.json == {'message': 'Token has been revoked'}
