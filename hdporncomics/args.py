import os
import sys
import argparse
import ast
import re
from importlib.metadata import version

__version__ = version(__package__ or __name__)


def valid_directory(directory: str):
    try:
        return os.chdir(directory)
    except:
        raise argparse.ArgumentTypeError(
            'couldn\'t change directory to "{}"'.format(directory)
        )


def conv_curl_header_to_requests(src: str):
    r = re.search(r"^\s*([A-Za-z0-9_-]+)\s*:(.*)$", src)
    if r is None:
        return None
    return {r[1]: r[2].strip()}


def conv_curl_cookie_to_requests(src: str):
    r = re.search(r"^\s*([A-Za-z0-9_-]+)\s*=(.*)$", src)
    if r is None:
        return None
    return {r[1]: r[2].strip()}


def valid_header(src: str) -> dict:
    r = conv_curl_header_to_requests(src)
    if r is None:
        raise argparse.ArgumentTypeError('Invalid header "{}"'.format(src))
    return r


def valid_cookie(src: str) -> dict:
    r = conv_curl_cookie_to_requests(src)
    if r is None:
        raise argparse.ArgumentTypeError('Invalid cookie "{}"'.format(src))
    return r


def argparser():
    parser = argparse.ArgumentParser(
        description="Tool for downloading from hdporncomics.com",
        add_help=False,
    )

    parser.add_argument(
        "urls",
        metavar="URL",
        type=str,
        nargs="*",
        help="url pointing to source",
    )

    general = parser.add_argument_group("General")
    general.add_argument(
        "-h",
        "--help",
        action="help",
        help="Show this help message and exit",
    )
    general.add_argument(
        "-v",
        "--version",
        action="version",
        version=__version__,
        help="Print program version and exit",
    )
    general.add_argument(
        "-t",
        "--threads",
        metavar="NUM",
        type=int,
        help="download images using NUM of threads",
        default=1,
    )

    files = parser.add_argument_group("Files")
    files.add_argument(
        "-d",
        "--directory",
        metavar="DIR",
        type=valid_directory,
        help="Change directory to DIR",
    )
    files.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="forcefully overwrite files",
    )
    files.add_argument(
        "--no-num-images",
        action="store_true",
        help="Don't rename images to their order number with leading zeroes, keep the original name",
    )

    types = parser.add_argument_group("Types")
    types.add_argument(
        "--chapter",
        action="append",
        metavar="URL",
        type=str,
        help="Treats the following url as manhwa chapter",
        default=[],
    )
    types.add_argument(
        "--manhwa",
        action="append",
        metavar="URL",
        type=str,
        help="Treats the following url as manhwa",
        default=[],
    )
    types.add_argument(
        "--comic",
        action="append",
        metavar="URL",
        type=str,
        help="Treats the following url as comic",
        default=[],
    )
    types.add_argument(
        "--pages",
        action="append",
        metavar="URL",
        type=str,
        help="Treats the following url as pages of comics/manhwas",
        default=[],
    )

    settings = parser.add_argument_group("Settings")
    settings.add_argument(
        "--images-only",
        action="store_true",
        help="ignore all metadata, save only images",
    )
    settings.add_argument(
        "--noimages",
        action="store_true",
        help="download only metadata",
    )
    settings.add_argument(
        "--nochapters",
        action="store_true",
        help="do not download chapters for manhwas",
    )
    settings.add_argument(
        "--comment-limit",
        metavar="NUM",
        type=int,
        help="limit amount of pages of comics traversed, set to -1 for all",
        default=0,
    )
    settings.add_argument(
        "--pages-max",
        metavar="NUM",
        type=int,
        help="set max number of pages traversed in pages of comics/manhwas",
        default=-1,
    )

    request_set = parser.add_argument_group("Request settings")
    request_set.add_argument(
        "-w",
        "--wait",
        metavar="SECONDS",
        type=float,
        help="Sets waiting time for each request to SECONDS",
    )
    request_set.add_argument(
        "-W",
        "--wait-random",
        metavar="MILISECONDS",
        type=int,
        help="Sets random waiting time for each request to be at max MILISECONDS",
    )
    request_set.add_argument(
        "-r",
        "--retries",
        metavar="NUM",
        type=int,
        help="Sets number of retries for failed request to NUM",
    )
    request_set.add_argument(
        "--retry-wait",
        metavar="SECONDS",
        type=float,
        help="Sets interval between each retry",
    )
    request_set.add_argument(
        "-m",
        "--timeout",
        metavar="SECONDS",
        type=float,
        help="Sets request timeout",
    )
    request_set.add_argument(
        "-k",
        "--insecure",
        action="store_false",
        help="Ignore ssl errors",
    )
    request_set.add_argument(
        "-L",
        "--location",
        action="store_true",
        help="Allow for redirections, can be dangerous if credentials are passed in headers",
    )
    request_set.add_argument(
        "-A",
        "--user-agent",
        metavar="UA",
        type=str,
        help="Sets custom user agent",
    )
    request_set.add_argument(
        "-x",
        "--proxies",
        metavar="DICT",
        type=lambda x: dict(ast.literal_eval(x)),
        help='Set requests proxies dictionary, e.g. -x \'{"http":"127.0.0.1:8080","ftp":"0.0.0.0"}\'',
    )
    request_set.add_argument(
        "-H",
        "--header",
        metavar="HEADER",
        type=valid_header,
        action="append",
        help="Set header, can be used multiple times e.g. -H 'User: Admin' -H 'Pass: 12345'",
    )
    request_set.add_argument(
        "-b",
        "--cookie",
        metavar="COOKIE",
        type=valid_cookie,
        action="append",
        help="Set cookie, can be used multiple times e.g. -b 'auth=8f82ab' -b 'PHPSESSID=qw3r8an829'",
    )

    return parser
