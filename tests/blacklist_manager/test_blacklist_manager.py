"""
This module implements the blacklist manager testing.
"""

__author__ = "Marc Bermejo"
__credits__ = ["Marc Bermejo"]
__license__ = "GPL-3.0"
__version__ = "0.0.1"
__maintainer__ = "Marc Bermejo"
__email__ = "mbermejo@bcn3dtechnologies.com"
__status__ = "Development"


from flask_jwt_extended import create_access_token, create_refresh_token


def test_blacklist_manager(db_manager, jwt_blacklist_manager):
    user = db_manager.get_users(id=1)
    user_access_token = create_access_token(user.identity)
    user_refresh_token = create_refresh_token(user.identity)

    printer = db_manager.get_printers(id=1)
    printer_access_token = create_access_token(printer.identity)
    printer_refresh_token = create_refresh_token(printer.identity)

    assert jwt_blacklist_manager.check_if_token_is_revoked(user_access_token, encoded=True)
    assert jwt_blacklist_manager.check_if_token_is_revoked(printer_access_token, encoded=True)

    jwt_blacklist_manager.add_token_set(user_access_token, user_refresh_token, access_encoded=True,
                                        refresh_encoded=True)
    jwt_blacklist_manager.add_token_set(printer_access_token, printer_refresh_token, access_encoded=True,
                                        refresh_encoded=True)

    assert not jwt_blacklist_manager.check_if_token_is_revoked(user_access_token, encoded=True)
    assert not jwt_blacklist_manager.check_if_token_is_revoked(user_refresh_token, encoded=True)
    assert not jwt_blacklist_manager.check_if_token_is_revoked(printer_access_token, encoded=True)
    assert not jwt_blacklist_manager.check_if_token_is_revoked(printer_refresh_token, encoded=True)

    jwt_blacklist_manager.revoke_refresh_token(user_refresh_token)

    assert jwt_blacklist_manager.check_if_token_is_revoked(user_access_token, encoded=True)
    assert jwt_blacklist_manager.check_if_token_is_revoked(user_refresh_token, encoded=True)
    assert not jwt_blacklist_manager.check_if_token_is_revoked(printer_access_token, encoded=True)
    assert not jwt_blacklist_manager.check_if_token_is_revoked(printer_refresh_token, encoded=True)

    new_printer_access_token = create_access_token(printer.identity)
    jwt_blacklist_manager.update_refresh_associated_access_token(printer_refresh_token, new_printer_access_token)

    assert jwt_blacklist_manager.check_if_token_is_revoked(user_access_token, encoded=True)
    assert jwt_blacklist_manager.check_if_token_is_revoked(user_refresh_token, encoded=True)
    assert jwt_blacklist_manager.check_if_token_is_revoked(printer_access_token, encoded=True)
    assert not jwt_blacklist_manager.check_if_token_is_revoked(new_printer_access_token, encoded=True)
    assert not jwt_blacklist_manager.check_if_token_is_revoked(printer_refresh_token, encoded=True)
