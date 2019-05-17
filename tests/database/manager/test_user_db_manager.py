"""
This module implements the user data related database manager testing.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"


def _add_user(db_manager):
    user = db_manager.insert_user("test-user", "Test User", "test@test.com", "1234", is_admin=False)
    return user


def test_user_db_manager(db_manager):
    expected_user = _add_user(db_manager)

    user = db_manager.get_users(isAdmin=False)
    assert expected_user == user[0]

    user = db_manager.get_users(username="test-user")
    assert expected_user == user
    assert user.verify_password("1234")

    db_manager.update_user(user, email="test-user@test.com", password="abcd")
    user = db_manager.get_users(username="test-user")
    assert user.email == "test-user@test.com"
    assert user.verify_password("abcd")

    db_manager.delete_user(user)
    user = db_manager.get_users(username="test-user")
    assert user is None
