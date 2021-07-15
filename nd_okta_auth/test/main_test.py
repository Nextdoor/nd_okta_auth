from __future__ import unicode_literals

import sys
import unittest

from nd_okta_auth import main

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock


class MainTest(unittest.TestCase):

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

    @mock.patch('nd_okta_auth.auth.login')
    @mock.patch('nd_okta_auth.main.get_config_parser')
    def test_entry_point(self, config_mock, auth_login):
        # Give
        fake_parser = mock.MagicMock(name='fake_parser')
        fake_parser.name = 'eng'
        fake_parser.org = 'org'
        fake_parser.appid = 'appid'
        fake_parser.username = 'username'
        fake_parser.debug = True
        fake_parser.reup = False
        config_mock.return_value = fake_parser
        # When
        with self.assertRaises(SystemExit):
            main.entry_point()
        # Then
        auth_login.assert_called_with(aws_profile='eng',
                                      okta_appid='appid',
                                      okta_org='org',
                                      username='username',
                                      reup=False, debug=True)
