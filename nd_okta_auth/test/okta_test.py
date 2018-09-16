from __future__ import unicode_literals

import sys
import unittest

import requests

from nd_okta_auth.okta import EmptyInput
from nd_okta_auth import factor, okta

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

# Miniaturized versions of the Okta response objects... they are too large to
# really store here, and its not necessary.
MFA_ENROLL_RESPONSE = {
    'status': 'MFA_ENROLL',
    'stateToken': 'token',
}

MFA_REQUIRED_RESPONSE = {
    'status': 'MFA_REQUIRED',
    '_embedded': {
        'factors': [
            {
                'factorType': 'test_factor',
                'id': 'abcd',
            }
        ]
    },
    'stateToken': 'token',
}

MFA_REQUIRED_RESPONSE_TWOFACTORS = {
    'status': 'MFA_REQUIRED',
    '_embedded': {
        'factors': [
            {
                'factorType': 'factor_one',
                'id': '1',
            },
            {
                'factorType': 'factor_two',
                'id': '2',
            }
        ]
    },
    'stateToken': 'token',
}


class OktaTest(unittest.TestCase):

    def test_init_blank_inputs(self):
        with self.assertRaises(EmptyInput):
            okta.Okta(organization='', username='test', password='test')

        with self.assertRaises(okta.EmptyInput):
            okta.Okta(organization=None, username='test', password='test')

    def test_auth_bad_password(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        resp = requests.Response()
        resp.status_code = 401
        resp.body = 'Bad Password'
        client._request.side_effect = requests.exceptions.HTTPError(
            response=resp)

        with self.assertRaises(okta.InvalidPassword):
            client.auth()

    def test_set_token(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock(name='session')
        client.set_token(SUCCESS_RESPONSE)
        self.assertEquals(client.session_token, 'XXXTOKENXXX')

    def test_auth(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='request')
        client._request.side_effect = [SUCCESS_RESPONSE]

        ret = client.auth()
        self.assertEquals(ret, None)

    def test_auth_requires_mfa_enroll(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='request')
        client._request.side_effect = [MFA_ENROLL_RESPONSE]

        with self.assertRaises(okta.UnknownError):
            client.auth()

    def test_auth_mfa_verify(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='request')
        client._request.side_effect = [MFA_REQUIRED_RESPONSE]

        test_factor = mock.MagicMock(name='test_factor')
        test_factor.name.return_value = 'test_factor'
        test_factor.verify.return_value = SUCCESS_RESPONSE

        client.supported_factors = [test_factor]
        client.auth()

        test_factor.verify.assert_called_with('abcd', 'token', sleep=1)
        self.assertEquals(client.session_token, 'XXXTOKENXXX')

    def test_auth_mfa_verify_fail(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='request')
        client._request.side_effect = [MFA_REQUIRED_RESPONSE]

        test_factor = mock.MagicMock(name='test_factor')
        test_factor.name.return_value = 'test_factor'
        test_factor.verify.side_effect = factor.FactorVerificationFailed

        client.supported_factors = [test_factor]
        with self.assertRaises(okta.ExhaustedFactors):
            client.auth()

        self.assertEquals(client.session_token, None)

    def test_verify_no_supported_factors(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='request')
        client._request.side_effect = [MFA_REQUIRED_RESPONSE]

        test_factor = mock.MagicMock(name='test_factor')
        test_factor.name.return_value = 'phone'
        test_factor.verify.side_effect = factor.FactorVerificationFailed

        client.supported_factors = [test_factor]
        with self.assertRaises(okta.ExhaustedFactors):
            client.auth()

        self.assertEquals(client.session_token, None)

    def test_auth_http_timeout(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='request')
        client._request.side_effect = [MFA_REQUIRED_RESPONSE]

        test_factor = mock.MagicMock(name='test_factor')
        test_factor.name.return_value = 'test_factor'
        test_factor.verify.side_effect = requests.exceptions.ReadTimeout

        client.supported_factors = [test_factor]
        with self.assertRaises(okta.ExhaustedFactors):
            client.auth()

        self.assertEquals(client.session_token, None)

    def test_auth_verify_interrupt(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='request')
        client._request.side_effect = [MFA_REQUIRED_RESPONSE_TWOFACTORS]

        factor_one = mock.MagicMock(name='factor_one')
        factor_one.name.return_value = 'factor_one'
        factor_one.verify.side_effect = KeyboardInterrupt

        factor_two = mock.MagicMock(name='factor_two')
        factor_two.name.return_value = 'factor_two'
        factor_two.verify.return_value = SUCCESS_RESPONSE

        client.supported_factors = [factor_one, factor_two]
        client.auth()

        factor_two.verify.assert_called_with('2', 'token', sleep=1)
        self.assertEquals(client.session_token, 'XXXTOKENXXX')

    def test_request_good_response(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock(name='session')

        # Ultimately this is the dict we want to get back
        expected_dict = {'ok': True}

        # Create a fake requests.post() response object mock that returns the
        # expected_dict above when json() is called
        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.json.return_value = expected_dict

        client.session.post.return_value = fake_response_object
        ret = client._request('/test', {'test': True})

        # Validate that the call went out as expected, with the supplied input
        client.session.post.assert_called_with(
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json'},
            json={'test': True},
            url='https://organization.okta.com/api/v1/test',
            allow_redirects=False)

        # Validate that we got back the expected_dict
        self.assertEquals(ret, expected_dict)

    def test_request_with_full_url(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock(name='session')

        # Ultimately this is the dict we want to get back
        expected_dict = {'ok': True}

        # Create a fake requests.post() response object mock that returns the
        # expected_dict above when json() is called
        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.json.return_value = expected_dict

        client.session.post.return_value = fake_response_object
        ret = client._request('http://test/test', {'test': True})

        # Validate that the call went out as expected, with the supplied input
        client.session.post.assert_called_with(
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json'},
            json={'test': True},
            url='http://test/test',
            allow_redirects=False)

        # Validate that we got back the expected_dict
        self.assertEquals(ret, expected_dict)

    def test_request_bad_response(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock(name='session')

        class TestExc(Exception):
            '''Test Exception'''

        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.raise_for_status.side_effect = TestExc()

        client.session.post.return_value = fake_response_object
        with self.assertRaises(TestExc):
            client._request('/test', {'test': True})
