import logging
import unittest
from unittest import mock

from nd_okta_auth import auth, aws, okta
from nd_okta_auth.auth import login, user_input


class AuthTest(unittest.TestCase):

    def test_setup_logger(self):
        # Simple execution test - make sure that the logger code executes and
        # returns a root logger. No mocks used here, want to ensure that the
        # options passed to the logger are valid.
        ret = auth.setup_logging()
        self.assertEquals(type(ret), type(logging.getLogger()))

    @mock.patch('nd_okta_auth.auth.user_input')
    @mock.patch('nd_okta_auth.aws.Session')
    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('getpass.getpass')
    def test_multirole(self, pass_mock,
                       okta_mock, aws_mock, input_mock):
        # First call to this is the password. Second call is the mis-typed
        # passcode. Third call is a valid passcode.
        pass_mock.side_effect = ['test_password']
        input_mock.side_effect = '0'

        # Just mock out the entire Okta object, we won't really instantiate it
        fake_okta = mock.MagicMock(name='OktaSaml')
        okta_mock.return_value = fake_okta
        aws_mock.return_value = mock.MagicMock(name='aws_mock')

        # Throw MultipleRoles to validate actions when there are multiple roles
        mocked_session = aws_mock.return_value
        mocked_session.assume_role.side_effect = [aws.MultipleRoles(), None]

        # Return multiple roles
        mocked_session.available_roles = mock.Mock()
        roles = [{'role': '1', 'principle': ''},
                 {'role': '2', 'principle': ''}]
        mocked_session.available_roles.return_value = roles

        _run_auth_login()

        # Ensure that getpass was called once for the password
        pass_mock.assert_has_calls([
            mock.call(),
        ])

        # Ensure that user_input was called for the role selection
        input_mock.assert_has_calls([
            mock.call('Select a role from above: '),
        ])

    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('getpass.getpass')
    def test_bad_password(self, pass_mock, okta_mock):
        pass_mock.return_value = 'test_password'

        # Just mock out the entire Okta object, we won't really instantiate it
        fake_okta = mock.MagicMock(name='fake_okta')
        fake_okta.auth.side_effect = okta.InvalidPassword
        okta_mock.return_value = fake_okta

        with self.assertRaises(okta.InvalidPassword):
            _run_auth_login()

    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('getpass.getpass')
    def test_exhausted_factors(self, pass_mock, okta_mock):
        pass_mock.return_value = 'test_password'

        # Just mock out the entire Okta object, we won't really instantiate it
        fake_okta = mock.MagicMock(name='fake_okta')
        fake_okta.auth.side_effect = okta.ExhaustedFactors
        okta_mock.return_value = fake_okta

        with self.assertRaises(okta.ExhaustedFactors):
            _run_auth_login()

    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('getpass.getpass')
    def test_bad_input(self, pass_mock, okta_mock):
        # Pretend that we got some bad input...
        pass_mock.return_value = ''
        okta_mock.side_effect = okta.EmptyInput

        with self.assertRaises(okta.EmptyInput):
            _run_auth_login()

    @mock.patch('nd_okta_auth.auth.input')
    def test_input(self, mock_input):
        mock_input.return_value = 'test'
        self.assertEqual('test', user_input('input test'))


def _run_auth_login():
    login(aws_profile='eng',
          okta_appid='appid',
          okta_org='org',
          username='username',
          reup=False)
