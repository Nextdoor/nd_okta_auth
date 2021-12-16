from __future__ import unicode_literals
import getpass
import logging
import sys
import time
import requests
from builtins import input

import rainbow_logging_handler

from nd_okta_auth import okta
from nd_okta_auth import aws
from nd_okta_auth.metadata import __desc__, __version__


def user_input(text):
    """Wraps input() making testing support of py2 and py3 easier"""
    return input(text)


def setup_logging():
    """Returns back a pretty color-coded logger"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = rainbow_logging_handler.RainbowLoggingHandler(sys.stdout)
    fmt = "%(asctime)-10s (%(levelname)s) %(message)s"
    formatter = logging.Formatter(fmt)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def login(
    aws_profile: str,
    okta_appid: str,
    okta_org: str,
    username: str,
    reup: bool,
    debug: bool = False,
):
    # Generate our logger first, and write out our app name and version
    log = setup_logging()
    log.info("%s v%s" % (__desc__, __version__))

    if debug:
        log.setLevel(logging.DEBUG)

    # Ask the user for their password.. we do this once at the beginning, and
    # we keep it in memory for as long as this tool is running. Its never ever
    # written out or cached to disk anywhere.
    password = getpass.getpass()

    # Generate our initial OktaSaml client and handle any exceptions thrown.
    # Generally these are input validation issues.
    try:
        okta_client = okta.OktaSaml(okta_org, username, password)
    except okta.EmptyInput:
        log.error("Cannot enter a blank string for any input")
        raise

    # Authenticate the Okta client. If necessary, we will ask for MFA input.
    try:
        okta_client.auth()
    except okta.InvalidPassword:
        log.error("Invalid Username ({user}) or Password".format(user=username))
        raise
    except okta.ExhaustedFactors as e:
        log.error(e)
        raise

    # Once we're authenticated with an OktaSaml client object, we can use that
    # object to get a fresh SAMLResponse repeatedly and refresh our AWS
    # Credentials.
    session = None
    role_selection = None
    while True:
        # If an AWS Session object has been created already, lets check if its
        # still valid. If it is, sleep a bit and skip to the next execution of
        # the loop.
        if session and session.is_valid:
            log.debug("Credentials are still valid, sleeping")
            time.sleep(15)
            continue

        log.info("Getting SAML Assertion from {org}".format(org=okta_org))

        try:
            assertion = okta_client.get_assertion(
                appid=okta_appid, apptype="amazon_aws"
            )
            session = aws.Session(assertion, profile=aws_profile)

            # If role_selection is set we're in a reup loop. Re-set the role on
            # the session to prevent the user being prompted for the role again
            # on each subsequent renewal.
            if role_selection is not None:
                session.set_role(role_selection)

            session.assume_role()

        except aws.MultipleRoles:
            log.warning("Multiple AWS roles found; please select one")
            roles = session.available_roles()
            for role_index, role in enumerate(roles):
                print("[{}] Role: {}".format(role_index, role["role"]))
            role_selection = user_input("Select a role from above: ")
            session.set_role(role_selection)
            session.assume_role()
        except requests.exceptions.ConnectionError:
            log.warning("Connection error... will retry")
            time.sleep(5)
            continue

        # If we're not running in re-up mode, once we have the assertion
        # and creds, go ahead and quit.
        if not reup:
            break

        log.info("Reup enabled, sleeping...")
        time.sleep(5)
