import logging

import requests
from six.moves import input

from nd_okta_auth.factor import Factor

log = logging.getLogger(__name__)


def user_input(text):
    """Wraps input() making testing support of py2 and py3 easier"""
    return input(text)


class TotpFactor(Factor):
    def get_passcode(self):
        return user_input("Time-based one-time passcode: ")

    def name(self):
        return "token:software:totp"

    def verify(self, fid, state_token, sleep):
        """Validates an Okta user with Passcode-based MFA.

        Takes in the supplied Factor ID (fid), State Token and user supplied
        Passcode, and validates the auth. If successful, sets the session
        token. If invalid, raises an exception.

        Args:
            fid: Okta Factor ID (returned in the PasscodeRequired exception)
            state_token: State Tken (returned in the PasscodeRequired
            exception)
            sleep: not used
        Returns:
            Response from okta
        """

        while True:
            passcode = self.get_passcode()
            if len(passcode) != 6:
                log.error("Passcodes must be 6 digits")
                continue

            path = "/authn/factors/{fid}/verify".format(fid=fid)
            data = {"fid": fid, "stateToken": state_token, "passCode": passcode}
            try:
                return self._request(path, data)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    log.error("Invalid Passcode Detected")
                    continue
                raise e
