from __future__ import unicode_literals

import sys
import unittest

import fido2

from nd_okta_auth.factor import u2f as factor

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
    'sessionToken': 'XXXTOKENXXX'
}

CHALLENGE_RESPONSE = {
    'status': 'MFA_CHALLENGE',
    '_embedded': {
        'factor': {
            'profile': {
                'credentialId': 'asfodiuhdwacdas',
                'version': 'U2F_V2',
                'appId': 'https://foobar.okta.com'
            },
            "_embedded": {
                "challenge": {
                    'nonce': 'anonce',
                    'timeoutSeconds': 20
                }
            },
            'id': '123',
            'factorType': 'u2f',
            'provider': 'FIDO',
            'vendorName': 'FIDO'
        }
    },
    'expiresAt': '2017-07-24T17:05:59.000Z',
    'stateToken': 'XXXTOKENXXX',
}

REJECTED_RESPONSE = {
    'status': 'REJECTED',
    '_links': {
        'next': {
            'href': 'https://foobar.okta.com/api/v1/authn/factors/X/verify',
        }
    },
    'stateToken': 'token',
}


class OktaTest(unittest.TestCase):
    def test_push_name(self):
        u2f_factor = factor.U2fFactor('foobar')
        self.assertEqual('u2f', u2f_factor.name())

    def test_u2f_success(self):
        u2f_factor = factor.U2fFactor('foobar')

        # Mock out the U2F device
        mock_device = mock.MagicMock(name='mock_device')
        u2f_factor._get_devices = mock.MagicMock(name='_get_devices')
        u2f_factor._get_devices.return_value = [mock_device].__iter__()

        # Mock out U2F client
        mock_client = mock.MagicMock(name='mock_client')
        u2f_factor._get_client = mock.MagicMock(name='_get_client')
        u2f_factor._get_client.return_value = mock_client
        mock_client.sign.return_value = {"clientData": "foo",
                                         "signatureData": "bar"}

        # Mock call to Okta API
        u2f_factor._request = mock.MagicMock(name='_request')
        u2f_factor._request.side_effect = [
            CHALLENGE_RESPONSE,
            SUCCESS_RESPONSE,
        ]

        # Run code
        ret = u2f_factor.verify('123', 'XXXTOKENXXX', 0.1)

        # Check results
        self.assertEqual(ret, SUCCESS_RESPONSE)

        u2f_factor._get_client.assert_called_once_with(mock_device,
                                                       'https://foobar'
                                                       '.okta.com')
        registered_keys = [
            {'version': 'U2F_V2', 'keyHandle': 'asfodiuhdwacdas'}]
        mock_client.sign.assert_called_once_with('https://foobar.okta.com',
                                                 'anonce', registered_keys)

        calls = [
            mock.call('/authn/factors/123/verify',
                      {'fid': '123', 'stateToken': 'XXXTOKENXXX'}),

            mock.call('/authn/factors/123/verify',
                      {'stateToken': 'XXXTOKENXXX',
                       'clientData': 'foo',
                       'signatureData': 'bar'})
        ]
        u2f_factor._request.assert_has_calls(calls)

    def test_u2f_wait(self):
        u2f_factor = factor.U2fFactor('foobar')

        # Mock out the U2F device
        mock_device = mock.MagicMock(name='mock_device')
        u2f_factor._get_devices = mock.MagicMock(name='_get_devices')
        u2f_factor._get_devices.return_value = [None, None, None, None,
                                                mock_device].__iter__()

        # Mock out U2F client
        mock_client = mock.MagicMock(name='mock_client')
        u2f_factor._get_client = mock.MagicMock(name='_get_client')
        u2f_factor._get_client.return_value = mock_client
        mock_client.sign.return_value = {"clientData": "foo",
                                         "signatureData": "bar"}

        # Mock call to Okta API
        u2f_factor._request = mock.MagicMock(name='_request')
        u2f_factor._request.side_effect = [
            CHALLENGE_RESPONSE,
            SUCCESS_RESPONSE,
        ]

        # Run code
        ret = u2f_factor.verify('123', 'XXXTOKENXXX', 0.1)

        # Check results
        self.assertEqual(ret, SUCCESS_RESPONSE)

    def test_u2f_client_error(self):
        u2f_factor = factor.U2fFactor('foobar')

        # Mock out the U2F device
        mock_device = mock.MagicMock(name='mock_device')
        u2f_factor._get_devices = mock.MagicMock(name='_get_devices')
        u2f_factor._get_devices.return_value = [mock_device].__iter__()

        # Mock out U2F client
        mock_client = mock.MagicMock(name='mock_client')
        u2f_factor._get_client = mock.MagicMock(name='_get_client')
        u2f_factor._get_client.return_value = mock_client
        mock_client.sign.side_effect = fido2.client.ClientError(4)

        # Mock call to Okta API
        u2f_factor._request = mock.MagicMock(name='_request')
        u2f_factor._request.side_effect = [
            CHALLENGE_RESPONSE
        ]

        # Run code
        with self.assertRaises(factor.FactorVerificationFailed):
            u2f_factor.verify('123', 'XXXTOKENXXX', 0.1)

        # Check results
        u2f_factor._get_client.assert_called_once_with(mock_device,
                                                       'https://foobar'
                                                       '.okta.com')
        calls = [
            mock.call('/authn/factors/123/verify',
                      {'fid': '123', 'stateToken': 'XXXTOKENXXX'})
        ]
        u2f_factor._request.assert_has_calls(calls)

    def test_u2f_rejected(self):
        u2f_factor = factor.U2fFactor('foobar')

        # Mock out the U2F device
        mock_device = mock.MagicMock(name='mock_device')
        u2f_factor._get_devices = mock.MagicMock(name='_get_devices')
        u2f_factor._get_devices.return_value = [mock_device].__iter__()

        # Mock out U2F client
        mock_client = mock.MagicMock(name='mock_client')
        u2f_factor._get_client = mock.MagicMock(name='_get_client')
        u2f_factor._get_client.return_value = mock_client
        mock_client.sign.return_value = {"clientData": "foo",
                                         "signatureData": "bar"}

        # Mock call to Okta API
        u2f_factor._request = mock.MagicMock(name='_request')
        u2f_factor._request.side_effect = [
            CHALLENGE_RESPONSE,
            REJECTED_RESPONSE,
        ]

        # Run code
        with self.assertRaises(factor.FactorVerificationFailed):
            ret = u2f_factor.verify('123', 'XXXTOKENXXX', 0.1)
            self.assertEqual(ret, REJECTED_RESPONSE)

        # Check results
        u2f_factor._get_client.assert_called_once_with(mock_device,
                                                       'https://foobar.'
                                                       'okta.com')
        registered_keys = [
            {'version': 'U2F_V2', 'keyHandle': 'asfodiuhdwacdas'}]
        mock_client.sign.assert_called_once_with('https://foobar.okta.com',
                                                 'anonce', registered_keys)

        calls = [
            mock.call('/authn/factors/123/verify', {'fid': '123',
                                                    'stateToken': 'XXXTOKENXXX'
                                                    }
                      ),

            mock.call('/authn/factors/123/verify',
                      {'stateToken': 'XXXTOKENXXX',
                       'clientData': 'foo',
                       'signatureData': 'bar'})
        ]
        u2f_factor._request.assert_has_calls(calls)

    def test_unexpected_status(self):
        u2f_factor = factor.U2fFactor('foobar')

        # Mock out the U2F device
        mock_device = mock.MagicMock(name='mock_device')
        u2f_factor._get_devices = mock.MagicMock(name='_get_devices')
        u2f_factor._get_devices.return_value = [mock_device].__iter__()

        # Mock out U2F client
        mock_client = mock.MagicMock(name='mock_client')
        u2f_factor._get_client = mock.MagicMock(name='_get_client')
        u2f_factor._get_client.return_value = mock_client
        mock_client.sign.return_value = {"clientData": "foo",
                                         "signatureData": "bar"}

        # Mock call to Okta API
        u2f_factor._request = mock.MagicMock(name='_request')
        u2f_factor._request.side_effect = [
            SUCCESS_RESPONSE,
        ]

        # Run code
        with self.assertRaises(factor.FactorVerificationFailed):
            ret = u2f_factor.verify('123', 'XXXTOKENXXX', 0.1)
            self.assertEqual(ret, REJECTED_RESPONSE)
