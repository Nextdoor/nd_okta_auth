import logging
import requests
import sys

if sys.version_info[0] < 3:  # Python 2
    from exceptions import Exception

log = logging.getLogger(__name__)

BASE_URL = "https://{organization}.okta.com"


class BaseException(Exception):
    """Base Exception for Okta Auth"""


class BaseOktaClient(object):
    def __init__(self, organization):
        self.base_url = BASE_URL.format(organization=organization)
        self.session = requests.Session()

    def _request(self, path, data=None):
        """Basic URL Fetcher for Okta

        Any HTTPError is raised immediately, otherwise the response is parsed
        as JSON and passed back as a dictionary.

        Args:
            path: The path at the base url to call
            data: Optional data to pass in as Post parameters

        Returns:
            The response in dict form.
        """
        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        if path.startswith("http"):
            url = path
        else:
            url = "{base}/api/v1{path}".format(base=self.base_url, path=path)

        resp = self.session.post(
            url=url, headers=headers, json=data, allow_redirects=False
        )

        resp_obj = resp.json()
        log.debug(resp_obj)

        resp.raise_for_status()
        return resp_obj
