from __future__ import unicode_literals
import unittest
import logging
import sys
from nd_okta_auth import main
from nd_okta_auth import aws
from nd_okta_auth import okta
if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock


class MainTest(unittest.TestCase):

    def test_setup_logger(self):
        # Simple execution test - make sure that the logger code executes and
        # returns a root logger. No mocks used here, want to ensure that the
        # options passed to the logger are valid.
        ret = main.setup_logging()
        self.assertEquals(type(ret), type(logging.getLogger()))

    def test_get_config_parser(self):
        # Simple execution test again - get the argument parser and make sure
        # it looks reasonably correct. Just validating that this function has
        # major typos.

        # Also simulates the _required_ options being passed in
        argv = [
            'nd_okta_auth.py',
            '-a', 'app/id',
            '-o', 'foobar',
            '-u', 'test'
        ]
        ret = main.get_config_parser(argv)
        self.assertEquals(ret.org, 'foobar')
        self.assertEquals(ret.appid, 'app/id')
        self.assertEquals(ret.username, 'test')

    @mock.patch('nd_okta_auth.aws.Session')
    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('nd_okta_auth.main.get_config_parser')
    @mock.patch('getpass.getpass')
    def test_entry_point(self, pass_mock, config_mock, okta_mock, aws_mock):
        # Mock out the password getter and return a simple password
        pass_mock.return_value = 'test_password'

        # Just mock out the entire Okta object, we won't really instantiate it
        okta_mock.return_value = mock.MagicMock()
        aws_mock.return_value = mock.MagicMock()

        # Mock out the arguments that were passed in
        fake_parser = mock.MagicMock(name='fake_parser')
        fake_parser.org = 'server'
        fake_parser.username = 'username'
        fake_parser.username = 'username'
        fake_parser.debug = True
        fake_parser.reup = 0
        config_mock.return_value = fake_parser

        main.main('test')

        okta_mock.assert_called_with('server', 'username', 'test_password')

    @mock.patch('nd_okta_auth.main.user_input')
    @mock.patch('nd_okta_auth.aws.Session')
    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('nd_okta_auth.main.get_config_parser')
    @mock.patch('getpass.getpass')
    def test_entry_point_multirole(self, pass_mock, config_mock,
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

        # Make sure we don't get stuck in a loop, always have to mock out the
        # reup option.
        fake_parser = mock.MagicMock(name='fake_parser')
        fake_parser.reup = 0
        config_mock.return_value = fake_parser

        main.main('test')

        # Ensure that getpass was called once for the password
        pass_mock.assert_has_calls([
            mock.call(),
        ])

        # Ensure that user_input was called for the role selection
        input_mock.assert_has_calls([
            mock.call('Select a role from above: '),
        ])

    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('nd_okta_auth.main.get_config_parser')
    @mock.patch('getpass.getpass')
    def test_entry_point_bad_password(self, pass_mock, config_mock, okta_mock):
        # Mock out the password getter and return a simple password
        pass_mock.return_value = 'test_password'

        # Just mock out the entire Okta object, we won't really instantiate it
        fake_okta = mock.MagicMock(name='fake_okta')
        fake_okta.auth.side_effect = okta.InvalidPassword
        okta_mock.return_value = fake_okta

        # Mock out the arguments that were passed in
        fake_parser = mock.MagicMock(name='fake_parser')
        config_mock.return_value = fake_parser

        with self.assertRaises(SystemExit):
            main.main('test')

    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('nd_okta_auth.main.get_config_parser')
    @mock.patch('getpass.getpass')
    def test_entry_point_bad_input(self, pass_mock, config_mock, okta_mock):
        # Pretend that we got some bad input...
        pass_mock.return_value = ''
        okta_mock.side_effect = okta.EmptyInput

        # Mock out the arguments that were passed in
        fake_parser = mock.MagicMock(name='fake_parser')
        config_mock.return_value = fake_parser

        with self.assertRaises(SystemExit):
            main.main('test')

    @mock.patch('nd_okta_auth.main.input')
    def test_input(self, mock_input):
        mock_input.return_value = 'test'
        self.assertEqual('test', main.user_input('input test'))

    @mock.patch('nd_okta_auth.main.main')
    def test_entry_point_func(self, main_mock):
        with self.assertRaises(SystemExit):
            main.entry_point()
