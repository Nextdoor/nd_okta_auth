"""
okta
^^^^

Handles the initial Okta authentication - throws appropriate errors in the
events of bad passwords, MFA requirements, etc.
"""

from __future__ import unicode_literals

import base64
import logging
import sys

import bs4
import requests

from nd_okta_auth import factor, base_client

if sys.version_info[0] < 3:  # Python 2
    from exceptions import Exception

log = logging.getLogger(__name__)


class UnknownError(Exception):
    """Some Expected Return Was Received"""


class EmptyInput(base_client.BaseException):
    """Invalid Input - Empty String Detected"""


class InvalidPassword(base_client.BaseException):
    """Invalid Password"""


class ExhaustedFactors(base_client.BaseException):
    """Failed to authenticate user with any factor"""


class Okta(base_client.BaseOktaClient):
    """Base Okta Login Object with MFA handling.

    This base login object handles connecting to Okta, authenticating a user,
    and optionally triggering MFA Authentication. No application specific logic
    is here, just the initial authentication and creation of a
    cookie-authenticated requests.Session() object.

    See OktaSaml for a more useful object.
    """

    def __init__(self, organization, username, password):
        base_client.BaseOktaClient.__init__(self, organization)
        log.debug("Base URL Set to: {url}".format(url=self.base_url))

        # Validate the inputs are reasonably sane
        for input in (organization, username, password):
            if input == "" or input is None:
                raise EmptyInput()

        self.username = username
        self.password = password
        self.supported_factors = factor.factors(organization)
        self.session_token = None

    def set_token(self, ret):
        """Parses an authentication response and stores the token.

        Parses a SUCCESSFUL authentication response from Okta and stores the
        token.

        args:
            ret: The response from Okta that we know is successful and contains
            a sessionToken
        """
        firstName = ret["_embedded"]["user"]["profile"]["firstName"]
        lastName = ret["_embedded"]["user"]["profile"]["lastName"]
        log.info(
            "Successfully authed {firstName} {lastName}".format(
                firstName=firstName, lastName=lastName
            )
        )
        self.session_token = ret["sessionToken"]

    def auth(self):
        """Performs an initial authentication against Okta.

        The initial Okta Login authentication is handled here - and optionally
        MFA authentication is triggered. If successful, this method stores a
        SessionToken. This SessionToken can be used to initiate a call to the
        "Embed Link" of an Okta Application.

        **Note ... Undocumented/Unclear Okta Behavior**
        If you use the SessionToken only to make your subsequent requests, its
        usable only once and then it expires. However, if you combine it with a
        long-lived SID cookie (which we do, by using reqests.Session() to make
        all of our web requests), then that SessionToken can be redeemd many
        times as long as you do it through the "Embed Links". See the OktaSaml
        client for an example.

            https://developer.okta.com/use_cases/authentication/
            session_cookie#visit-an-embed-link-with-the-session-token
        """
        path = "/authn"
        data = {"username": self.username, "password": self.password}
        try:
            ret = self._request(path, data)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise InvalidPassword()

        status = ret.get("status", None)

        if status == "SUCCESS":
            self.set_token(ret)
            return

        if status == "MFA_ENROLL" or status == "MFA_ENROLL_ACTIVATE":
            log.warning("User {u} needs to enroll in 2FA first".format(u=self.username))
            raise UnknownError()

        if status == "MFA_REQUIRED" or status == "MFA_CHALLENGE":
            # Factors enabled by the user
            enabled_factors = ret["_embedded"]["factors"]

            # Loop through locally supported factors
            for supported_factor in self.supported_factors:
                # filter enabled factors against support factors
                filtered_factors = list(
                    filter(
                        lambda x: x.get("factorType") == supported_factor.name(),
                        enabled_factors,
                    )
                )

                # Try authenticating with each enabled factor
                for enabled_factor in filtered_factors:
                    log.info(
                        "Authenticating with factor: {} id {}".format(
                            supported_factor.name(), enabled_factor["id"]
                        )
                    )

                    try:
                        ret = supported_factor.verify(
                            enabled_factor["id"], ret["stateToken"], sleep=1
                        )
                        self.set_token(ret)
                        return
                    except KeyboardInterrupt:
                        # Allow users to use MFA Push by breaking
                        # out of waiting for U2F device.
                        log.info(
                            "User skipping factor: {}".format(supported_factor.name())
                        )
                        continue
                    except factor.FactorVerificationFailed as e:
                        # Non fatal error that a factor failed to
                        # be verified.
                        log.error(e)
                        continue
                    except requests.exceptions.ReadTimeout:
                        log.error(
                            "HTTP timeout contacting Okta at {}".format(self.base_url)
                        )
                        continue

        raise ExhaustedFactors("Failed to verify with any MFA factor")


class OktaSaml(Okta):
    def assertion(self, saml):
        assertion = ""
        soup = bs4.BeautifulSoup(saml, "html.parser")
        for inputtag in soup.find_all("input"):
            if inputtag.get("name") == "SAMLResponse":
                assertion = inputtag.get("value")
        return base64.b64decode(assertion)

    def get_assertion(self, appid, apptype):
        path = "{url}/home/{apptype}/{appid}".format(
            url=self.base_url, apptype=apptype, appid=appid
        )
        resp = self.session.get(path, params={"onetimetoken": self.session_token})
        log.debug(resp.__dict__)

        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            log.error("Unknown error: {msg}".format(msg=str(e.response.__dict__)))
            raise UnknownError()

        return self.assertion(resp.text)
