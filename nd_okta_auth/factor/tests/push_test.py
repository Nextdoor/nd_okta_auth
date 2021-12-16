from __future__ import unicode_literals

import sys
import unittest

import requests

from nd_okta_auth.factor import push as factor

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock

# Successful response message from Okta when you have fully logged in
SUCCESS_RESPONSE = {
    "status": "SUCCESS",
    "expiresAt": "2017-07-24T17:05:59.000Z",
    "_embedded": {
        "user": {
            "profile": {
                "locale": "en",
                "lastName": "Foo",
                "login": "bob@foobar.com",
                "firstName": "Bob",
                "timeZone": "America/Los_Angeles",
            },
            "id": "XXXIDXXX",
        }
    },
    "sessionToken": "XXXTOKENXXX",
}

MFA_CHALLENGE_RESPONSE_OKTA_VERIFY = {
    "status": "MFA_REQUIRED",
    "_embedded": {
        "factors": [
            {
                "factorType": "push",
                "id": "abcd",
            }
        ]
    },
    "stateToken": "token",
}
MFA_WAITING_RESPONSE = {
    "status": "MFA_CHALLENGE",
    "factorResult": "WAITING",
    "_links": {
        "next": {
            "href": "https://foobar.okta.com/api/v1/authn/factors/X/verify",
        }
    },
    "stateToken": "token",
}
MFA_REJECTED_RESPONSE = {
    "status": "MFA_CHALLENGE",
    "factorResult": "REJECTED",
    "_links": {
        "next": {
            "href": "https://foobar.okta.com/api/v1/authn/factors/X/verify",
        }
    },
    "stateToken": "token",
}


class OktaTest(unittest.TestCase):
    def test_push_name(self):
        push_factor = factor.PushFactor("foobar")
        self.assertEqual("push", push_factor.name())

    def test_push_success(self):
        push_factor = factor.PushFactor("https://foobar.okta.com")
        push_factor._request = mock.MagicMock(name="_request")

        push_factor._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            SUCCESS_RESPONSE,
        ]

        ret = push_factor.verify("123", "token", 0.1)
        self.assertEqual(ret, SUCCESS_RESPONSE)

    def test_push_rejected(self):
        push_factor = factor.PushFactor("https://foobar.okta.com")
        push_factor._request = mock.MagicMock(name="_request")

        push_factor._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_REJECTED_RESPONSE,
        ]

        with self.assertRaises(factor.FactorVerificationFailed):
            push_factor.verify("123", "token", 0.1)

    def test_push_unknown_failure(self):
        push_factor = factor.PushFactor("https://foobar.okta.com")
        push_factor.get_passcode = mock.MagicMock(name="get_passcode")
        push_factor.get_passcode.return_value = 123456

        push_factor._request = mock.MagicMock(name="_request")

        resp = requests.Response()
        resp.status_code = 500
        resp.body = "Internal Server Error"
        push_factor._request.side_effect = requests.exceptions.HTTPError(response=resp)

        with self.assertRaises(requests.exceptions.HTTPError):
            push_factor.verify("123", "token", 0.1)
