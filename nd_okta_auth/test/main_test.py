import unittest
import mock

from nd_okta_auth import main
from nd_okta_auth import okta


class MainTest(unittest.TestCase):

    @mock.patch('nd_okta_auth.aws.Session')
    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('argparse.ArgumentParser')
    @mock.patch('getpass.getpass')
    def test_entry_point(self, pass_mock, arg_mock, okta_mock, aws_mock):
        # Mock out the password getter and return a simple password
        pass_mock.return_value = 'test_password'

        # Just mock out the entire Okta object, we won't really instantiate it
        okta_mock.return_value = mock.MagicMock()
        aws_mock.return_value = mock.MagicMock()

        # Mock out the arguments that were passed in
        fake_parser = mock.MagicMock(name='fake_parser')
        fake_parser.parse_args().server = 'server'
        fake_parser.parse_args().username = 'username'
        fake_parser.parse_args().username = 'username'
        fake_parser.parse_args().debug = True
        fake_parser.parse_args().reup = 0
        arg_mock.return_value = fake_parser

        main.main('test')

        okta_mock.assert_called_with('server', 'username', 'test_password')

    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('argparse.ArgumentParser')
    @mock.patch('getpass.getpass')
    def test_entry_point_bad_input(self, pass_mock, arg_mock, okta_mock):
        # Pretend that we got some bad input...
        pass_mock.return_value = ''
        okta_mock.side_effect = okta.EmptyInput

        # Mock out the arguments that were passed in
        fake_parser = mock.MagicMock(name='fake_parser')
        fake_parser.parse_args().server = 'server'
        fake_parser.parse_args().username = 'username'
        fake_parser.parse_args().username = 'username'
        fake_parser.parse_args().debug = True
        fake_parser.parse_args().reup = 0
        arg_mock.return_value = fake_parser

        with self.assertRaises(SystemExit):
            main.main('test')
