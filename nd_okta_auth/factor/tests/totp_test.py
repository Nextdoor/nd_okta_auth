from __future__ import unicode_literals

import sys
import unittest

import requests

from nd_okta_auth.factor import totp as factor

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock

# Successful response message from Okta when you have fully logged in
SUCCESS_RESPONSE = {
    'status': 'SUCCESS',
    'expiresAt': '2017-07-24T17:05:59.000Z',
    '_embedded': {
        'user': {
            'profile': {
                'locale': 'en',
                'lastName': 'Foo',
                'login': 'bob@foobar.com',
                'firstName': 'Bob', 'timeZone':
                    'America/Los_Angeles'},
            'id': 'XXXIDXXX'
        }
    },
    'sessionToken': 'XXXTOKENXXX'}

TOTP_REJECTED_RESPONSE = {
    'status': 'MFA_CHALLENGE',
    'factorResult': 'REJECTED',
    '_links': {
        'next': {
            'href': 'https://foobar.okta.com/api/v1/authn/factors/X/verify',
        }
    },
    'stateToken': 'token'
}


class OktaTest(unittest.TestCase):
    def test_totp_name(self):
        totp_factor = factor.TotpFactor('foobar')
        self.assertEqual('token:software:totp', totp_factor.name())

    @mock.patch('nd_okta_auth.factor.totp.user_input')
    def test_get_passcode(self, input_mock):
        totp_factor = factor.TotpFactor('foobar')
        input_mock.return_value = '123456'

        totp_factor._request = mock.MagicMock(name='_request')
        totp_factor._request.side_effect = [
            SUCCESS_RESPONSE,
        ]

        totp_factor.verify('123', 'token', 0.1)
        input_mock.assert_called_with('Time-based one-time passcode: ')

    def test_totp_success(self):
        totp_factor = factor.TotpFactor('foobar')
        totp_factor.get_passcode = mock.MagicMock(name='get_passcode')
        totp_factor.get_passcode.return_value = '123456'

        totp_factor._request = mock.MagicMock(name='_request')
        totp_factor._request.side_effect = [
            SUCCESS_RESPONSE,
        ]

        ret = totp_factor.verify('123', 'token', 0.1)
        self.assertEqual(ret, SUCCESS_RESPONSE)

    def test_totp_unknown_failure(self):
        totp_factor = factor.TotpFactor('foobar')
        totp_factor.get_passcode = mock.MagicMock(name='get_passcode')
        totp_factor.get_passcode.return_value = '123456'

        totp_factor._request = mock.MagicMock(name='_request')

        resp = requests.Response()
        resp.status_code = 500
        resp.body = "Internal Server Error"
        totp_factor._request.side_effect = requests.exceptions.HTTPError(
            response=resp)

        with self.assertRaises(requests.exceptions.HTTPError):
            totp_factor.verify('123', 'token', 0.1)

    def test_totp_try_again(self):
        totp_factor = factor.TotpFactor('foobar')
        totp_factor.get_passcode = mock.MagicMock(name='get_passcode')
        totp_factor.get_passcode.side_effect = ['123', '123456', '654321']

        totp_factor._request = mock.MagicMock(name='_request')

        resp = requests.Response()
        resp.status_code = 403
        totp_factor._request.side_effect = [requests.exceptions.HTTPError(
            response=resp), SUCCESS_RESPONSE]

        totp_factor.verify('123', 'token', 0.1)
