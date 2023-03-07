from __future__ import unicode_literals
from nd_okta_auth.metadata import __desc__, __version__
from nd_okta_auth.auth import user_input,setup_logging
import rainbow_logging_handler
from nd_okta_auth import okta
from nd_okta_auth import aws
from builtins import input
import webbrowser
import requests
import getpass
import logging
import base64
import time
import sys
import bs4


def _assertion(saml):
    assertion = ""
    soup = bs4.BeautifulSoup(saml, "html.parser")
    for inputtag in soup.find_all("input"):
        if inputtag.get("name") == "SAMLResponse":
            assertion = inputtag.get("value")
    return base64.b64decode(assertion)

def get_access_token(client_id,authorize_response,okta_aws_app_id,headers,okta_org_url,log):
    attempts = 0 
    while True:
        attempts+=1
        data = {
            'client_id': f'{client_id}',
            'device_code':authorize_response.json()['device_code'],
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        }

        oauth2_response = requests.post(f'{okta_org_url}/oauth2/v1/token', headers=headers, data=data)
        log.debug(oauth2_response.json())
        print("Waiting to get approval from Okta")
        if "error" not in  oauth2_response.json() :
            
            break
        time.sleep(3)
        if attempts > 100:
            raise Exception("Timeout waiting for approval from Okta")
            break
    if "access_token" in  oauth2_response.json():
        data = {
            'actor_token': oauth2_response.json()['access_token'],
            'actor_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'audience': f'urn:okta:apps:{okta_aws_app_id}', 
            'client_id': client_id,
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'requested_token_type': 'urn:okta:oauth:token-type:web_sso_token',
            'subject_token': oauth2_response.json()['id_token'],
            'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
        }
        grant_check_response = requests.post(f'{okta_org_url}/oauth2/v1/token', headers=headers, data=data)
        access_token = grant_check_response.json()['access_token']
        return access_token

def login(
    aws_profile: str,
    okta_appid: str,
    okta_org: str,

    reup: bool,
    oidc_id:str,
    domain:str = "okta.com",
    debug: bool = False,

):
    # Generate our logger first, and write out our app name and version
    log = setup_logging()
    log.info("%s v%s" % (__desc__, __version__))
    log.debug("Running in debug mode for oie_oidc_auth")

    if debug:
        log.setLevel(logging.DEBUG)

    client_id =oidc_id
    okta_aws_app_id = okta_appid
    okta_org_url = f"https://{okta_org}.{domain}"

    log.debug("client_id: %s,okta_aws_app_id: %s,okta_org_url: %s" % (client_id, okta_aws_app_id,okta_org_url))

    headers = {
        'Accept': 'application/json',
        'User-Agent': 'okta-aws-cli/0.2.1 golang/go1.17.2 darwin/arm64',
    }

    data = {
        'client_id': f'{client_id}',
        'scope': 'openid okta.apps.sso okta.apps.read',
    }
    log.debug(f'{okta_org_url}/oauth2/v1/device/authorize')
    authorize_response = requests.post(f'{okta_org_url}/oauth2/v1/device/authorize', headers=headers, data=data)
    print("Please go to the following URL and enter the code:")
    print(authorize_response.json()['verification_uri_complete'])
    webbrowser.open(authorize_response.json()['verification_uri_complete'])
    log.debug(authorize_response.json())
    try:
        access_token= get_access_token(client_id,authorize_response,okta_aws_app_id,headers,okta_org_url,log)
    except Exception as e:
        log.error(e)
        raise
  
    # Once we're authenticated with an OktaSaml client object, we can use that
    # object to get a fresh SAMLResponse repeatedly and refresh our AWS
    # Credentials.
    session = None
    role_selection = None

    while True:
        # If an AWS Session object has been created already, lets check if its
        # still valid. If it is, sleep a bit and skip to the next execution of
        # the loop.
        if session and session.is_valid:
            log.debug("Credentials are still valid, sleeping")
            time.sleep(15)
            continue

        log.info("Getting SAML Assertion from {org}".format(org=okta_org))

        try:
            url = f'{okta_org_url}/login/token/sso?token='+ access_token
            #Make a GET request
            # the headers may not be necessary but I added them just in case
            r = requests.get(url,headers=headers)
            
            session = aws.Session(_assertion(r.text), profile=aws_profile)

            # If role_selection is set we're in a reup loop. Re-set the role on
            # the session to prevent the user being prompted for the role again
            # on each subsequent renewal.
            if role_selection is not None:
                session.set_role(role_selection)

            session.assume_role()

        except aws.MultipleRoles:
            log.warning("Multiple AWS roles found; please select one")
            roles = session.available_roles()
            for role_index, role in enumerate(roles):
                print("[{}] Role: {}".format(role_index, role["role"]))
            role_selection = user_input("Select a role from above: ")
            session.set_role(role_selection)
            session.assume_role()
        except requests.exceptions.ConnectionError:
            log.warning("Connection error... will retry")
            time.sleep(5)
            continue

        # If we're not running in re-up mode, once we have the assertion
        # and creds, go ahead and quit.
        if not reup:
            break

        log.info("Reup enabled, sleeping...")
        time.sleep(5)
