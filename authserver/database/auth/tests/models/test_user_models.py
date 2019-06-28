"""
This module implements the user data related database models testing.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.2"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"

from ...initial_values import user_initial_values
from ...models import (
    UserAuth
)


def add_user(session):
    user = UserAuth(
        id=2,
        email="test@test.com",
        isAdmin=False,
    )
    user.hash_password("1234")

    session.add(user)
    session.commit()

    return user


def test_user_model(session):
    expected_users = user_initial_values()

    for i in range(len(expected_users)):
        expected_users[i].id = i + 1

    user = add_user(session)
    expected_users.append(user)
    
    str(user)

    assert user.id > 0
    assert user.verify_password("1234")
    assert user.identity == {
        "type": "user",
        "id": user.id,
        "is_admin": user.isAdmin
    }

    users = UserAuth.query.all()
    
    assert len(users) == len(expected_users)
    
    for i in range(len(expected_users)):
        assert expected_users[i].id == users[i].id
        assert expected_users[i].email == users[i].email
        assert expected_users[i].isAdmin == users[i].isAdmin
        assert expected_users[i].enabled == users[i].enabled
