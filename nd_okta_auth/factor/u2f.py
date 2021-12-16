import logging
import time

from fido2.client import U2fClient, ClientError
from fido2.hid import CtapHidDevice

from nd_okta_auth.factor import Factor, FactorVerificationFailed

log = logging.getLogger(__name__)


class U2fFactor(Factor):
    def name(self):
        return "u2f"

    def _get_devices(self):
        return CtapHidDevice.list_devices()

    def _get_client(self, dev, appId):
        return U2fClient(dev, appId)

    def verify(self, fid, state_token, sleep):
        """Validates user with Okta using user's U2F hardware device.

        This method is meant to be called by self.auth() if a Login session
        requires MFA, and the users profile supports U2F.

        We wait for a U2F device to be plugged into USB, request a challenge
        nonce from Okta, pass the challenge to the U2F device, and finally
        send back the challenge response to Okta.  If its accepted, we write
        out our SessionToken.

        Args:
            fid: Okta Factor ID used to trigger the push
            state_token: State Token allowing us to trigger the push
            sleep: amount of seconds to wait between checking for U2F hardware
                   keep to be plugged in.
        """
        path = self.verify_path.format(fid=fid)

        # Wait for U2F device to be plugged in before continuing on
        dev = None
        while True:
            dev = next(self._get_devices(), None)
            if dev:
                break
            log.info("Waiting for FIDO U2F device to be plugged in.")
            time.sleep(sleep)

        # Request U2F nonce/challenge from Okta
        log.info("Requesting U2F challenge nonce from Okta")
        data = {"fid": fid, "stateToken": state_token}
        ret = self._request(path, data)

        if ret["status"] != "MFA_CHALLENGE":
            raise FactorVerificationFailed("Expected MFA challenge")

        # Get U2F device to sign nonce/challenge
        appId = self.base_url
        client = self._get_client(dev, appId)

        nonce = ret["_embedded"]["factor"]["_embedded"]["challenge"]["nonce"]
        credentialId = ret["_embedded"]["factor"]["profile"]["credentialId"]
        registered_keys = [{"version": "U2F_V2", "keyHandle": credentialId}]

        log.warning("Touch your authenticator device now...")

        try:
            r = client.sign(appId, nonce, registered_keys)
        except ClientError:
            raise FactorVerificationFailed(
                "U2F devices failed to "
                "sign request. Have you "
                'registered it with "{}"?'.format(appId)
            )

        # Send challenge response back to Okta
        data = {
            "stateToken": state_token,
            "clientData": r.get("clientData"),
            "signatureData": r.get("signatureData"),
        }

        ret = self._request(path, data)

        if ret.get("status") != "SUCCESS":
            raise FactorVerificationFailed()

        return ret
