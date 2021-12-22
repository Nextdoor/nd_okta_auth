#!/usr/bin/env python

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright 2017 Nextdoor.com, Inc
import argparse
from future.moves import sys
from nd_okta_auth import auth, base_client
from nd_okta_auth.metadata import __version__


def get_config_parser(argv):
    """Returns a configured ArgumentParser for the CLI options"""
    epilog = (
        "**Application ID**\n"
        "The ApplicationID is actually a two part piece of the redirect URL \n"
        "that Okta uses when you are logged into the Web UI. If you mouse \n"
        "over the appropriate Application and see a URL that looks like \n"
        "this. \n"
        "\n"
        "\thttps://foobar.okta.com/home/amazon_aws/0oaciCSo1d8/123?...\n"
        "\n"
        'You would enter in "0oaciCSo1d8/123" as your Application ID.\n'
    )

    arg_parser = argparse.ArgumentParser(
        prog=argv[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
        description="Okta Auther",
    )

    # Get rid of the default optional arguments section that always shows up.
    # Its not necessary, and confusing to have optional arguments listed first.
    #   https://stackoverflow.com/questions/24180527/
    #   argparse-required-arguments-listed-under-optional-arguments
    arg_parser._action_groups.pop()

    required_args = arg_parser.add_argument_group("required arguments")
    required_args.add_argument(
        "-o",
        "--org",
        type=str,
        help=(
            "Okta Organization Name - ie, if your login"
            " URL is https://foobar.okta.com, enter in "
            "foobar here"
        ),
        required=True,
    )
    required_args.add_argument(
        "-u",
        "--username",
        type=str,
        help=(
            "Okta Login Name - either bob@foobar.com, "
            "or just bob works too, depending on your "
            "organization settings."
        ),
        required=True,
    )
    required_args.add_argument(
        "-a",
        "--appid",
        type=str,
        help=(
            'The "redirect link" Application ID  - '
            "this can be found by mousing over the "
            "application in Okta's Web UI. See "
            "details below for more help."
        ),
        required=True,
    )

    optional_args = arg_parser.add_argument_group("optional arguments")
    optional_args.add_argument("-V", "--version", action="version", version=__version__)
    optional_args.add_argument(
        "-D",
        "--debug",
        action="store_true",
        help=(
            "Enable DEBUG logging - note, this is "
            "extremely verbose and exposes credentials "
            "so be careful here!"
        ),
        default=False,
    )
    optional_args.add_argument(
        "-r",
        "--reup",
        action="store_true",
        help=("Automatically re-up the AWS creds before" "they expire."),
        default=0,
    )
    optional_args.add_argument(
        "-n", "--name", type=str, help="AWS Profile Name", default="default"
    )

    config = arg_parser.parse_args(args=argv[1:])
    return config


def entry_point():
    """Zero-argument entry point for use with setuptools/distribute."""
    config = get_config_parser(sys.argv)
    try:
        auth.login(
            aws_profile=config.name,
            okta_appid=config.appid,
            okta_org=config.org,
            username=config.username,
            reup=config.reup,
            debug=config.debug,
        )
    except base_client.BaseException:
        sys.exit(1)


if __name__ == "__main__":
    entry_point()
