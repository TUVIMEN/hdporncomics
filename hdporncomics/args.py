#!/usr/bin/env python
# by Dominik Stanisław Suchora <hexderm@gmail.com>
# License: GNU GPLv3

import os
import argparse
from importlib.metadata import version

from treerequests import args_section

__version__ = version(__package__ or __name__)


def valid_directory(directory: str):
    try:
        return os.chdir(directory)
    except:
        raise argparse.ArgumentTypeError(
            'couldn\'t change directory to "{}"'.format(directory)
        )


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

    args_section(parser)

    return parser
