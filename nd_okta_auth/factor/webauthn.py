import base64
import logging
import time

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from fido2.client import Fido2Client, ClientError
from fido2.hid import CtapHidDevice
from fido2.webauthn import PublicKeyCredentialRequestOptions

from fido2.utils import websafe_decode

from nd_okta_auth.factor import Factor, FactorVerificationFailed

log = logging.getLogger(__name__)


class WebauthnFactor(Factor):
    def name(self):
        return "webauthn"

    def _get_devices(self):
        return CtapHidDevice.list_devices()

    def _get_client(self, dev, appId):
        return Fido2Client(dev, appId)

    def verify(self, fid, state_token, sleep):
        """Validates user with Okta using user's webauthn hardware device.

        This method is meant to be called by self.auth() if a Login session
        requires MFA, and the users profile supports webauthn.

        We wait for a webauthn device to be plugged into USB, request a
        challenge nonce from Okta, pass the challenge to the webauthn device,
        and finally send back the challenge response to Okta.  If its accepted,
        we write out our SessionToken.

        Args:
            fid: Okta Factor ID used to trigger the push
            state_token: State Token allowing us to trigger the push
            sleep: amount of seconds to wait between checking for webauthn
                   hardware keep to be plugged in.
        """
        path = self.verify_path.format(fid=fid)

        # Wait for webauthn device to be plugged in before continuing on
        dev = None
        while True:
            dev = next(self._get_devices(), None)
            if dev:
                break
            log.info("Waiting for FIDO webauthn device to be plugged in.")
            time.sleep(sleep)

        # Request webauthn nonce/challenge from Okta
        log.info("Requesting webauthn challenge nonce from Okta")
        data = {"fid": fid, "stateToken": state_token}
        ret = self._request(path, data)

        if ret["status"] != "MFA_CHALLENGE":
            raise FactorVerificationFailed("Expected MFA challenge")

        # Get webauthn device to sign nonce/challenge
        appId = self.base_url
        client = self._get_client(dev, appId)
        nonce = ret["_embedded"]["factor"]["_embedded"]["challenge"]["challenge"]
        credential_id = ret["_embedded"]["factor"]["profile"]["credentialId"]
        # Add extra padding to credential_id as it may not have enough
        credential_id = base64.urlsafe_b64decode(credential_id + "====")

        allow_list = [{"type": "public-key", "id": credential_id}]
        rp_id = urlparse(appId).hostname

        log.warning("Touch your authenticator device now...")
        try:
            challenge = websafe_decode(nonce)
            options = PublicKeyCredentialRequestOptions(
                challenge=challenge, rp_id=rp_id, allow_credentials=allow_list
            )

            assertions, client_data = client.get_assertion(options)
        except ClientError:
            raise FactorVerificationFailed(
                "webauthn devices failed to "
                "sign request. Have you "
                'registered it with "{}"?'.format(appId)
            )

        # Send challenge response back to Okta
        assert len(assertions) == 1
        ad = base64.b64encode(assertions[0].auth_data)
        cd = base64.b64encode(client_data)
        sig = base64.b64encode(assertions[0].signature)

        data = {
            "stateToken": state_token,
            "clientData": cd.decode(),
            "authenticatorData": ad.decode(),
            "signatureData": sig.decode(),
        }

        ret = self._request(path, data)

        if ret.get("status") != "SUCCESS":
            raise FactorVerificationFailed()

        return ret
