from __future__ import unicode_literals

import sys
import unittest

from nd_okta_auth import main, base_client

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
        argv = ["nd_okta_auth.py", "-a", "app/id", "-o", "foobar", "-u", "test"]
        ret = main.get_config_parser(argv)
        self.assertEquals(ret.org, "foobar")
        self.assertEquals(ret.appid, "app/id")
        self.assertEquals(ret.username, "test")

    @mock.patch("nd_okta_auth.auth.login")
    @mock.patch("nd_okta_auth.main.get_config_parser")
    def test_entry_point(self, config_mock, auth_login):
        # Given
        fake_parser = mock.MagicMock(name="fake_parser")
        config_mock.return_value = fake_parser
        auth_login.side_effect = base_client.BaseException()
        # Except
        with self.assertRaises(SystemExit):
            main.entry_point()
