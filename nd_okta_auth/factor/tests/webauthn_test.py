from __future__ import unicode_literals

import base64
import sys
import unittest

import fido2
from fido2.utils import websafe_encode
from fido2.webauthn import PublicKeyCredentialRequestOptions

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

CREDENTIAL_ID_STR = b'ababababababa'
CREDENTIAL_ID_ENC = 'YWJhYmFiYWJhYmFiYQ=='
CREDENTIAL_ID_DEC = base64.urlsafe_b64decode(CREDENTIAL_ID_ENC)

NONCE_STR = b'anonce'
NONCE_ENC = websafe_encode(NONCE_STR)

CHALLENGE_RESPONSE = {
    'status': 'MFA_CHALLENGE',
    '_embedded': {
        'factor': {
            'profile': {
                'credentialId': CREDENTIAL_ID_ENC,
                'authenticatorName': 'yekibuy'
            },
            "_embedded": {
                "challenge": {
                    'challenge': NONCE_ENC,
                    'extensions': {}
                }
            },
            'id': '123',
            'factorType': 'webauthn',
            'provider': 'FIDO',
            'vendorName': 'FIDO'
        }
    },
    'policy': {
        'allowRememberDevice': True,
        'rememberDeviceLifetimeInMinutes': 0,
        'rememberDeviceByDefault': False,
        'factorsPolicyInfo': {}
      },
    'stateToken': 'XXXTOKENXXX',
    'expiresAt': '2017-07-24T17:05:59.000Z'
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


class dotdict(dict):
    """ dot.notation access to dictionary attributes
        source: https://stackoverflow.com/a/23689767
    """
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class OktaTest(unittest.TestCase):
    def test_push_name(self):
        webauthn = factor.WebauthnFactor('foobar')
        self.assertEqual('webauthn', webauthn.name())

    def test_webauthn_success(self):
        webauthn = factor.WebauthnFactor('foobar')

        # Mock out the webauthn device
        mock_device = mock.MagicMock(name='mock_device')
        webauthn._get_devices = mock.MagicMock(name='_get_devices')
        webauthn._get_devices.return_value = [mock_device].__iter__()

        # Mock out webauthn client
        mock_client = mock.MagicMock(name='mock_client')
        webauthn._get_client = mock.MagicMock(name='_get_client')
        webauthn._get_client.return_value = mock_client

        assertions = [dotdict({'auth_data': b'foo', 'signature': b'bar'})]
        client_data = b'baz'
        mock_client.get_assertion.return_value = (assertions, client_data)

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

        allow_list = [{
            'type': 'public-key',
            'id': CREDENTIAL_ID_STR
        }]

        options = PublicKeyCredentialRequestOptions(
            challenge=NONCE_STR,
            rp_id='foobar.okta.com',
            allow_credentials=allow_list
        )

        mock_client.get_assertion.assert_called_once_with(options)

        calls = [
            mock.call('/authn/factors/123/verify',
                      {'fid': '123', 'stateToken': 'XXXTOKENXXX'}),

            mock.call('/authn/factors/123/verify',
                      {'stateToken': 'XXXTOKENXXX',
                       'clientData': 'YmF6',
                       'signatureData': 'YmFy',
                       'authenticatorData': 'Zm9v'})
        ]
        webauthn._request.assert_has_calls(calls)

    def test_webauthn_wait(self):
        webauthn = factor.WebauthnFactor('foobar')

        # Mock out the webauthn device
        mock_device = mock.MagicMock(name='mock_device')
        webauthn._get_devices = mock.MagicMock(name='_get_devices')
        webauthn._get_devices.return_value = [None, None, None, None,
                                              mock_device].__iter__()

        # Mock out webauthn client
        mock_client = mock.MagicMock(name='mock_client')
        webauthn._get_client = mock.MagicMock(name='_get_client')
        webauthn._get_client.return_value = mock_client
        assertions = [dotdict({'auth_data': b'foo', 'signature': b'bar'})]
        client_data = b'baz'
        mock_client.get_assertion.return_value = (assertions, client_data)

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

        # Mock out the webauthn device
        mock_device = mock.MagicMock(name='mock_device')
        webauthn._get_devices = mock.MagicMock(name='_get_devices')
        webauthn._get_devices.return_value = [mock_device].__iter__()

        # Mock out webauthn client
        mock_client = mock.MagicMock(name='mock_client')
        webauthn._get_client = mock.MagicMock(name='_get_client')
        webauthn._get_client.return_value = mock_client
        mock_client.get_assertion.side_effect = fido2.client.ClientError(4)

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

        # Mock out the webauthn device
        mock_device = mock.MagicMock(name='mock_device')
        webauthn._get_devices = mock.MagicMock(name='_get_devices')
        webauthn._get_devices.return_value = [mock_device].__iter__()

        # Mock out webauthn client
        mock_client = mock.MagicMock(name='mock_client')
        webauthn._get_client = mock.MagicMock(name='_get_client')
        webauthn._get_client.return_value = mock_client

        # Mock call to Okta API
        webauthn._request = mock.MagicMock(name='_request')
        webauthn._request.side_effect = [
            CHALLENGE_RESPONSE,
            REJECTED_RESPONSE,
        ]

        assertions = [dotdict({'auth_data': b'foo', 'signature': b'bar'})]
        client_data = b'baz'
        mock_client.get_assertion.return_value = (assertions, client_data)

        # Run code
        with self.assertRaises(factor.FactorVerificationFailed):
            ret = webauthn.verify('123', 'XXXTOKENXXX', 0.1)
            self.assertEqual(ret, REJECTED_RESPONSE)

        # Check results
        webauthn._get_client.assert_called_once_with(mock_device,
                                                     'https://foobar.'
                                                     'okta.com')

        calls = [
            mock.call('/authn/factors/123/verify', {'fid': '123',
                                                    'stateToken': 'XXXTOKENXXX'
                                                    }
                      ),

            mock.call('/authn/factors/123/verify',
                      {'stateToken': 'XXXTOKENXXX',
                       'clientData': 'YmF6',
                       'signatureData': 'YmFy',
                       'authenticatorData': 'Zm9v'})
        ]
        webauthn._request.assert_has_calls(calls)

    def test_unexpected_status(self):
        webauthn = factor.WebauthnFactor('foobar')

        # Mock out the webauthn device
        mock_device = mock.MagicMock(name='mock_device')
        webauthn._get_devices = mock.MagicMock(name='_get_devices')
        webauthn._get_devices.return_value = [mock_device].__iter__()

        # Mock out webauthn client
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
