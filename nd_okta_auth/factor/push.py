import logging
import time

from nd_okta_auth.factor import Factor, FactorVerificationFailed

log = logging.getLogger(__name__)


class PushFactor(Factor):
    def name(self):
        return "push"

    def verify(self, fid, state_token, sleep):
        """Triggers an Okta Push Verification and waits.

        This method is meant to be called by self.auth() if a Login session
        requires MFA, and the users profile supports Okta Push with Verify.

        We trigger the push, and then immediately go into a wait loop. Each
        time we loop around, we pull the latest status for that push event. If
        its Declined, we will throw an error. If its accepted, we write out our
        SessionToken.

        Args:
            fid: Okta Factor ID used to trigger the push
            state_token: State Token allowing us to trigger the push
            sleep: amount of time to sleep between checking for push status
        """
        log.warning("Okta Verify Push being sent...")
        path = self.verify_path.format(fid=fid)
        data = {"fid": fid, "stateToken": state_token}
        ret = self._request(path, data)

        while ret["status"] != "SUCCESS":
            log.info("Waiting for Okta Verification...")
            time.sleep(sleep)

            if ret.get("factorResult", "REJECTED") == "REJECTED":
                raise FactorVerificationFailed("Okta Verify Push REJECTED")

            links = ret.get("_links")
            ret = self._request(links["next"]["href"], data)

        return ret
