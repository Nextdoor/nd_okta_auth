import abc
import logging

from nd_okta_auth import base_client


class FactorVerificationFailed(base_client.BaseException):
    """Failed to authenticate with second factor"""


log = logging.getLogger(__name__)


class Factor(base_client.BaseOktaClient):
    __metaclass__ = abc.ABCMeta

    verify_path = "/authn/factors/{fid}/verify"

    def __init__(self, organization):
        base_client.BaseOktaClient.__init__(self, organization)

    @abc.abstractmethod
    def name(self):
        """Name of the second factor. Must be same as Okta's `factorType`"""
        return

    @abc.abstractmethod
    def verify(self, fid, state_token, sleep):
        """Verify a user with a second factor."""
        return


def factors(organization):
    from nd_okta_auth.factor.u2f import U2fFactor  # noqa: F401
    from nd_okta_auth.factor.push import PushFactor  # noqa: F401
    from nd_okta_auth.factor.totp import TotpFactor  # noqa: F401
    from nd_okta_auth.factor.webauthn import WebauthnFactor  # noqa: F401

    return [
        WebauthnFactor(organization),
        U2fFactor(organization),
        PushFactor(organization),
        TotpFactor(organization),
    ]
