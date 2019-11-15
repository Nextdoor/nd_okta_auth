from __future__ import unicode_literals

import sys
import unittest

import fido2

from nd_okta_auth.factor import webauthn as factor

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
                    'challenge': 'anonce',
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
        webauthn = factor.WebauthnFactor('foobar')
        self.assertEqual('webauthn', webauthn.name())

    def test_webauthn_success(self):
        webauthn = factor.WebauthnFactor('foobar')

        # Mock out the U2F device
        mock_device = mock.MagicMock(name='mock_device')
        webauthn._get_devices = mock.MagicMock(name='_get_devices')
        webauthn._get_devices.return_value = [mock_device].__iter__()

        # Mock out U2F client
        mock_client = mock.MagicMock(name='mock_client')
        webauthn._get_client = mock.MagicMock(name='_get_client')
        webauthn._get_client.return_value = mock_client
        mock_client.sign.return_value = {"clientData": "foo",
                                         "signatureData": "bar"}

        # Mock call to Okta API
        webauthn._request = mock.MagicMock(name='_request')
        webauthn._request.side_effect = [
            CHALLENGE_RESPONSE,
            SUCCESS_RESPONSE,
        ]

        # Run code
        ret = webauthn.verify('123', 'XXXTOKENXXX', 0.1)

        # Check results
        self.assertEqual(ret, SUCCESS_RESPONSE)

        webauthn._get_client.assert_called_once_with(mock_device,
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
        webauthn._request.assert_has_calls(calls)

    def test_webauthn_wait(self):
        webauthn = factor.WebauthnFactor('foobar')

        # Mock out the U2F device
        mock_device = mock.MagicMock(name='mock_device')
        webauthn._get_devices = mock.MagicMock(name='_get_devices')
        webauthn._get_devices.return_value = [None, None, None, None,
                                              mock_device].__iter__()

        # Mock out U2F client
        mock_client = mock.MagicMock(name='mock_client')
        webauthn._get_client = mock.MagicMock(name='_get_client')
        webauthn._get_client.return_value = mock_client
        mock_client.sign.return_value = {"clientData": "foo",
                                         "signatureData": "bar"}

        # Mock call to Okta API
        webauthn._request = mock.MagicMock(name='_request')
        webauthn._request.side_effect = [
            CHALLENGE_RESPONSE,
            SUCCESS_RESPONSE,
        ]

        # Run code
        ret = webauthn.verify('123', 'XXXTOKENXXX', 0.1)

        # Check results
        self.assertEqual(ret, SUCCESS_RESPONSE)

    def test_webauthn_client_error(self):
        webauthn = factor.WebauthnFactor('foobar')

        # Mock out the U2F device
        mock_device = mock.MagicMock(name='mock_device')
        webauthn._get_devices = mock.MagicMock(name='_get_devices')
        webauthn._get_devices.return_value = [mock_device].__iter__()

        # Mock out U2F client
        mock_client = mock.MagicMock(name='mock_client')
        webauthn._get_client = mock.MagicMock(name='_get_client')
        webauthn._get_client.return_value = mock_client
        mock_client.sign.side_effect = fido2.client.ClientError(4)

        # Mock call to Okta API
        webauthn._request = mock.MagicMock(name='_request')
        webauthn._request.side_effect = [
            CHALLENGE_RESPONSE
        ]

        # Run code
        with self.assertRaises(factor.FactorVerificationFailed):
            webauthn.verify('123', 'XXXTOKENXXX', 0.1)

        # Check results
        webauthn._get_client.assert_called_once_with(mock_device,
                                                     'https://foobar'
                                                     '.okta.com')
        calls = [
            mock.call('/authn/factors/123/verify',
                      {'fid': '123', 'stateToken': 'XXXTOKENXXX'})
        ]
        webauthn._request.assert_has_calls(calls)

    def test_webauthn_rejected(self):
        webauthn = factor.WebauthnFactor('foobar')

        # Mock out the U2F device
        mock_device = mock.MagicMock(name='mock_device')
        webauthn._get_devices = mock.MagicMock(name='_get_devices')
        webauthn._get_devices.return_value = [mock_device].__iter__()

        # Mock out U2F client
        mock_client = mock.MagicMock(name='mock_client')
        webauthn._get_client = mock.MagicMock(name='_get_client')
        webauthn._get_client.return_value = mock_client
        mock_client.sign.return_value = {"clientData": "foo",
                                         "signatureData": "bar"}

        # Mock call to Okta API
        webauthn._request = mock.MagicMock(name='_request')
        webauthn._request.side_effect = [
            CHALLENGE_RESPONSE,
            REJECTED_RESPONSE,
        ]

        # Run code
        with self.assertRaises(factor.FactorVerificationFailed):
            ret = webauthn.verify('123', 'XXXTOKENXXX', 0.1)
            self.assertEqual(ret, REJECTED_RESPONSE)

        # Check results
        webauthn._get_client.assert_called_once_with(mock_device,
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
        webauthn._request.assert_has_calls(calls)

    def test_unexpected_status(self):
        webauthn = factor.WebauthnFactor('foobar')

        # Mock out the U2F device
        mock_device = mock.MagicMock(name='mock_device')
        webauthn._get_devices = mock.MagicMock(name='_get_devices')
        webauthn._get_devices.return_value = [mock_device].__iter__()

        # Mock out U2F client
        mock_client = mock.MagicMock(name='mock_client')
        webauthn._get_client = mock.MagicMock(name='_get_client')
        webauthn._get_client.return_value = mock_client
        mock_client.sign.return_value = {"clientData": "foo",
                                         "signatureData": "bar"}

        # Mock call to Okta API
        webauthn._request = mock.MagicMock(name='_request')
        webauthn._request.side_effect = [
            SUCCESS_RESPONSE,
        ]

        # Run code
        with self.assertRaises(factor.FactorVerificationFailed):
            ret = webauthn.verify('123', 'XXXTOKENXXX', 0.1)
            self.assertEqual(ret, REJECTED_RESPONSE)
