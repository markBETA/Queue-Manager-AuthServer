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


def _add_user(db_manager, user_id=2):
    user = db_manager.insert_user(user_id, "test@test.com", "1234", is_admin=False)
    return user


def test_user_db_manager(db_manager):
    expected_user = _add_user(db_manager)

    user = db_manager.get_users(isAdmin=False)
    assert expected_user == user[0]

    user = db_manager.get_users(email="test@test.com")
    assert expected_user == user
    assert user.verify_password("1234")

    admin_users_count = db_manager.count_admin_users()
    assert admin_users_count == 1

    db_manager.update_user(user, email="test-user@test.com", password="abcd", isAdmin=True)
    user = db_manager.get_users(email="test-user@test.com")
    assert user.id == expected_user.id
    assert user.verify_password("abcd")
    assert user.isAdmin is True

    admin_users_count = db_manager.count_admin_users()
    assert admin_users_count == 2

    another_user = _add_user(db_manager, user_id=3)
    db_manager.update_user(another_user, isAdmin=True)

    admin_users_count = db_manager.count_admin_users()
    assert admin_users_count == 3

    db_manager.update_user(another_user, isAdmin=False)

    admin_users_count = db_manager.count_admin_users()
    assert admin_users_count == 2

    db_manager.delete_user(user)
    user = db_manager.get_users(email="test-user@test.com")
    assert user is None
