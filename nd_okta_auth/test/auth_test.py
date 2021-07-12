import logging
import unittest

from nd_okta_auth import auth


class AuthTest(unittest.TestCase):

    def test_setup_logger(self):
        # Simple execution test - make sure that the logger code executes and
        # returns a root logger. No mocks used here, want to ensure that the
        # options passed to the logger are valid.
        ret = auth.setup_logging()
        self.assertEquals(type(ret), type(logging.getLogger()))
