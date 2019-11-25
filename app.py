#!/usr/bin/env python
"""
This is an example application of how to make use of Bottle to provide
sub-request authentication with NGINX, particularly with a Gitea
SQLite3 database.

Copyright (c) 2019, Robert Cope/Cope Systems.
License: Apache (see LICENSE file)
"""
from vendor import bottle
from sqlite3 import dbapi2 as sqlite
from argparse import ArgumentParser
import hashlib
import binascii
import datetime
import logging


app_argument_parser = ArgumentParser()
app_argument_parser.add_argument(
    "database_path", help="The SQLite3 database path."
)
app_argument_parser.add_argument(
    "-d", "--debug", action="store_true"
)
app_argument_parser.add_argument(
    "-q", "--quiet", action="store_true"
)
app_argument_parser.add_argument(
    "-H", "--host", default="127.0.0.1"
)
app_argument_parser.add_argument(
    "-p", "--port", default=9090
)

logger = logging.getLogger('')
start_dt = datetime.datetime.now()


# dict_factory used to return dictionaries
# instead of tuples from SQLite queries to
# ease getting specific column values later.
def dict_factory(cursor, row):
    d = dict()
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def create_connection(database_url):
    """
    Create a new SQLite3 connection, which
    should return rows as dictionaries.
    """
    connection = sqlite.connect(database_url)
    connection.row_factory = dict_factory
    return connection


def check_gitea_pbkdf2(passwd, row, debug=False):
    """
    Hash and compare a candidate password against
    a given Gitea user database record.
    """
    hashed = hashlib.pbkdf2_hmac(
        'sha256', bytes(passwd, encoding='utf-8'),
        bytes(row['salt'], encoding='utf-8'), 10000, 50
    )
    if debug:
        logger.debug(
            "hash result: {0} / expected: {1}"
            "".format(binascii.hexlify(hashed).decode('ascii'),
                      row['passwd'])
        )
    return binascii.hexlify(hashed).decode('ascii') == row['passwd']


def check_pass(connection, username, passwd, debug=False):
    """
    Check incoming username/password authentication
    using SQLite.

    :returns: True if authentication was successful, False otherwise.
    :rtype: bool
    """
    logger.info("Handling auth request for {0}".format(username))
    cursor = connection.cursor()
    try:

        cursor.execute(
            "SELECT * FROM user WHERE (lower_name = :un OR name = :un OR email = :un)"
            " AND is_active = 1 AND type = 0 AND prohibit_login = 0",
            {"un": username.strip()}
        )
        result = cursor.fetchone()
        if result:
            logger.info("Found matching user in database.")
            if result['passwd_hash_algo'] == "pbkdf2":
                logger.info("Attempt to hash password.")
                if check_gitea_pbkdf2(passwd, result, debug=debug):
                    logger.info("Successfully authenticated.")
                    return True
                else:
                    logger.info("Hash check failed.")
                    return False
            else:
                logger.warning("Found unknown hashing algo {0} in database!"
                               "".format(result['passwd_hash_algo']))
                # Don't know how to hash this.
                return False
        else:
            logger.info("No matching user found.")
            return False
    finally:
        cursor.close()


def build_app(database_url, debug=False):
    """
    Create a new instance of bottle and add the views necessary
    to do authentication.
    """
    app = bottle.Bottle()
    connection = create_connection(database_url)

    auth_partial = lambda un, pw: check_pass(
        connection, un, pw, debug=debug
    )

    @app.route("/", name="index")
    def index():
        return "Up since: {0}".format(start_dt)

    @app.route("/auth", name="auth_view")
    @bottle.auth_basic(auth_partial)
    def auth_view():
        return bottle.HTTPResponse(
            status=200,
            body="success"
        )

    return app


def main(app_args):
    """
    Set up logging and create and run our bottle auth app.
    """
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    if app_args.debug:
        logger.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    elif app_args.quiet:
        logger.setLevel(logging.WARNING)
        handler.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)
    logger.info("App starting up...")
    app = build_app(app_args.database_path, app_args.debug)
    logger.info("Starting run loop...")
    app.run(
        host=app_args.host, port=app_args.port
    )


if __name__ == "__main__":
    args = app_argument_parser.parse_args()
    main(args)
