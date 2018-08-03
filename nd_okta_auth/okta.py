'''
okta
^^^^

Handles the initial Okta authentication - throws appropriate errors in the
events of bad passwords, MFA requirements, etc.
'''

from __future__ import unicode_literals
import base64
import logging
import time
import sys
import bs4
import requests
if sys.version_info[0] < 3:  # Python 2
    from exceptions import Exception

log = logging.getLogger(__name__)

BASE_URL = 'https://{organization}.okta.com'


class BaseException(Exception):
    '''Base Exception for Okta Auth'''


class UnknownError(Exception):
    '''Some Expected Return Was Received'''


class EmptyInput(BaseException):
    '''Invalid Input - Empty String Detected'''


class InvalidPassword(BaseException):
    '''Invalid Password'''


class PasscodeRequired(BaseException):
    '''A 2FA Passcode Must Be Entered'''

    def __init__(self, fid, state_token):
        self.fid = fid
        self.state_token = state_token


class OktaVerifyRequired(BaseException):
    '''OktaVerify Authentication Is Required'''


class Okta(object):

    '''Base Okta Login Object with MFA handling.

    This base login object handles connecting to Okta, authenticating a user,
    and optionally triggering MFA Authentication. No application specific logic
    is here, just the initial authentication and creation of a
    cookie-authenticated requests.Session() object.

    See OktaSaml for a more useful object.
    '''

    def __init__(self, organization, username, password):
        self.base_url = BASE_URL.format(organization=organization)
        log.debug('Base URL Set to: {url}'.format(url=self.base_url))

        # Validate the inputs are reasonably sane
        for input in (organization, username, password):
            if input == '' or input is None:
                raise EmptyInput()

        self.username = username
        self.password = password
        self.session = requests.Session()

    def _request(self, path, data=None):
        '''Basic URL Fetcher for Okta

        Any HTTPError is raised immediately, otherwise the response is parsed
        as JSON and passed back as a dictionary.

        Args:
            path: The path at the base url to call
            data: Optional data to pass in as Post parameters

        Returns:
            The response in dict form.
        '''
        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}

        if path.startswith('http'):
            url = path
        else:
            url = '{base}/api/v1{path}'.format(base=self.base_url, path=path)

        resp = self.session.post(url=url, headers=headers, json=data,
                                 allow_redirects=False)

        resp_obj = resp.json()
        log.debug(resp_obj)

        resp.raise_for_status()
        return resp_obj

    def set_token(self, ret):
        '''Parses an authentication response and stores the token.

        Parses a SUCCESSFUL authentication response from Okta and stores the
        token.

        args:
            ret: The response from Okta that we know is successful and contains
            a sessionToken
        '''
        firstName = ret['_embedded']['user']['profile']['firstName']
        lastName = ret['_embedded']['user']['profile']['lastName']
        log.info('Successfully authed {firstName} {lastName}'.format(
            firstName=firstName, lastName=lastName))
        self.session_token = ret['sessionToken']

    def validate_mfa(self, fid, state_token, passcode):
        '''Validates an Okta user with Passcode-based MFA.

        Takes in the supplied Factor ID (fid), State Token and user supplied
        Passcode, and validates the auth. If successful, sets the session
        token. If invalid, raises an exception.

        Args:
            fid: Okta Factor ID (returned in the PasscodeRequired exception)
            state_token: State Tken (returned in the PasscodeRequired
            exception)
            passcode: The user-supplied Passcode to verify

        Returns:
            True/False whether or not authentication was successful
        '''
        if len(passcode) != 6:
            log.error('Passcodes must be 6 digits')
            return False

        path = '/authn/factors/{fid}/verify'.format(fid=fid)
        data = {'fid': fid,
                'stateToken': state_token,
                'passCode': passcode}
        try:
            ret = self._request(path, data)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                log.error('Invalid Passcode Detected')
                return False
            raise UnknownError(e.response.body)

        self.set_token(ret)
        return True

    def okta_verify_with_push(self, fid, state_token, sleep=1):
        '''Triggers an Okta Push Verification and waits.

        This metho is meant to be called by self.auth() if a Login session
        requires MFA, and the users profile supports Okta Push with Verify.

        We trigger the push, and then immediately go into a wait loop. Each
        time we loop around, we pull the latest status for that push event. If
        its Declined, we will throw an error. If its accepted, we write out our
        SessionToken.

        Args:
            fid: Okta Factor ID used to trigger the push
            state_token: State Token allowing us to trigger the push
        '''
        log.warning('Okta Verify Push being sent...')
        path = '/authn/factors/{fid}/verify'.format(fid=fid)
        data = {'fid': fid,
                'stateToken': state_token}
        ret = self._request(path, data)

        while ret['status'] != 'SUCCESS':
            log.info('Waiting for Okta Verification...')
            time.sleep(sleep)

            if ret.get('factorResult', 'REJECTED') == 'REJECTED':
                log.error('Okta Verify Push REJECTED')
                return False

            links = ret.get('_links')
            ret = self._request(links['next']['href'], data)

        self.set_token(ret)
        return True

    def auth_request(self):
        '''Performs a basic authentication call against Okta.

        This will return the json response of the authentication request.
        '''
        path = '/authn'
        data = {'username': self.username,
                'password': self.password}

        try:
            ret = self._request(path, data)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise InvalidPassword()
            raise

        return ret

    def auth(self, response=None, force_mfa_code=False):
        '''Performs an initial authentication against Okta.

        The initial Okta Login authentication is handled here - and optionally
        MFA authentication is triggered. If successful, this method stores a
        SessionToken. This SessionToken can be used to initiate a call to the
        "Embed Link" of an Okta Application.

        **Note ... Undocumented/Unclear Okta Behavior**
        If you use the SessionToken only to make your subsequent requests, its
        usable only once and then it expires. However, if you combine it with a
        long-lived SID cookie (which we do, by using reqests.Session() to make
        all of our web requests), then that SessionToken can be redeemd many
        times as long as you do it through the "Embed Links". See the OktaSaml
        client for an example.

            https://developer.okta.com/use_cases/authentication/
            session_cookie#visit-an-embed-link-with-the-session-token

        Args:
            response: Response from authentication request.
                If None, will do a new authentication request.
            force_mfa_code: Force using MFA rather than push notifications.
        '''
        if response is None:
            response = self.auth_request()

        status = response.get('status', None)

        if status == 'SUCCESS':
            self.set_token(response)
            return

        if status == 'MFA_ENROLL' or status == 'MFA_ENROLL_ACTIVATE':
            log.warning('User {u} needs to enroll in 2FA first'.format(
                u=self.username))
            raise UnknownError()

        if status == 'MFA_REQUIRED' or status == 'MFA_CHALLENGE':
            for factor in response['_embedded']['factors']:
                if factor['factorType'] == 'push' and not force_mfa_code:
                    try:
                        if self.okta_verify_with_push(factor['id'],
                                                      response['stateToken']):
                            return
                    except KeyboardInterrupt:
                        # Allow users to use MFA Passcode by
                        # breaking out of waiting for the push.
                        break

            for factor in response['_embedded']['factors']:
                if factor['factorType'] == 'token:software:totp':
                    raise PasscodeRequired(
                        fid=factor['id'],
                        state_token=response['stateToken'])

        raise UnknownError(status)


class OktaSaml(Okta):

    def assertion(self, saml):
        assertion = ''
        soup = bs4.BeautifulSoup(saml, 'html.parser')
        for inputtag in soup.find_all('input'):
            if inputtag.get('name') == 'SAMLResponse':
                assertion = inputtag.get('value')
        return base64.b64decode(assertion)

    def get_assertion(self, appid, apptype):
        path = '{url}/home/{apptype}/{appid}'.format(
            url=self.base_url, apptype=apptype, appid=appid)
        resp = self.session.get(path,
                                params={'onetimetoken': self.session_token})
        log.debug(resp.__dict__)

        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            log.error('Unknown error: {msg}'.format(
                msg=str(e.response.__dict__)))
            raise UnknownError()

        return self.assertion(resp.text)
