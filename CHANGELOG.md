Version 0.0.1
=============
    * Added the database manager and the defined models.
    * Added the blacklist manager to control the active tokens used for authenticate.
    * Added the api resources for create, edit and delete users and printers and for authenticate them.
    * Added a full unit test suite of the server.

Version 0.0.2 (BETA version)
============================
    * Swagger documentation revised and corrected.
    * App database module updated to v0.0.2
    * Blacklist manager module updated to v0.0.2
    * Updated the application factory.
    * Updated the configuration files structure.
    * Some minor bugs corrected
    * Improved the production environment deployment with Gunicorn.
    * Added the Domestic Data Streamers specific production config.

Version 0.1.0
=============
    * The blacklist manager isn't an external module anymore.
    * Added the /general namespace.
    * Now the check_access_token endpoints adds the X-Identity header with the token subject.
    * Minor error fixes.
    * Code refactoring.
