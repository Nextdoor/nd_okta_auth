# Nextdoor Okta Auth-er

## Development Setup

    $ virtualenv .venv
        $ source .venv/bin/activate
            $ pip install -r requirements.txt

### Running Tests

    $ nosetests -vv --with-coverage --cover-erase --cover-package=nd_okta_auth
