#!/usr/bin/env python
# by Dominik Stanisław Suchora <hexderm@gmail.com>
# License: GNU GPLv3

import sys
import os
from pathlib import Path
import json
from typing import Callable, Optional
from concurrent.futures import ThreadPoolExecutor

import treerequests

from .hdporncomics import hdporncomics
from .args import argparser


def warn(msg: str):
    print(msg, file=sys.stderr)


def guess(path: Path, hdpo: hdporncomics, url: str, settings: dict):
    r = hdpo.guess(url)

    if r is None:
        warn('Couldn\'t guess for "{}"'.format(url))
        return

    if r == hdpo.get_comic:
        comic(path, hdpo, url, settings)
    elif r == hdpo.get_manhwa:
        manhwa(path, hdpo, url, settings)
    elif r == hdpo.get_manhwa_chapter:
        chapter(path, hdpo, url, settings)
    elif r == hdpo.get_pages:
        pages(path, hdpo, url, settings)
    else:
        warn("Functionality not implemented in cli tool for {}".format(url))


def escape_path(path: str) -> str:
    return path.replace("/", "|")


def get_extension(url: str) -> str:
    ex = url.rsplit(".", maxsplit=1)
    if len(ex) != 2:
        return ""
    return ex[1]


def image_fname(url: str, i: int, offset: int, no_image_num: bool) -> str:
    if no_image_num:
        return os.path.basename(url)

    ex = get_extension(url)
    if len(ex) == 0:
        raise Exception('Image url "{}" has no extension'.format(url))
    numstr = str(i).zfill(offset)
    return "{}.{}".format(numstr, ex)


def path_writable(path: Path, force: bool, checktype: Callable) -> Optional[bool]:
    if os.path.exists(path):
        if not force and os.path.getsize(path) > 0:
            return False

        if not checktype(path):
            return False

        return None

    return True


def path_writable_file(path: Path, force: bool) -> Optional[bool]:
    return path_writable(path, force, os.path.isfile)


def path_writable_dir(path: Path, force: bool) -> Optional[bool]:
    return path_writable(path, force, os.path.isdir)


def image_writable(path: Path, force: bool) -> bool:
    r = path_writable_file(path, force)
    if force and r is False:
        raise Exception(
            'Path "{}" to the images is filled by non file type'.format(path)
        )

    return r is not False


def get_image(path: Path, hdpo: hdporncomics, url: str):
    r = hdpo.ses.get(url).content
    with open(path, "wb") as f:
        f.write(r)


def digits_count(n: int) -> int:
    r = 0
    while n != 0:
        n //= 10
        r += 1
    return r


def get_images(path: Path, hdpo: hdporncomics, urls: list[str], settings: dict):
    if settings["noimages"]:
        return

    offset = digits_count(len(urls))
    images = []

    for i, url in enumerate(urls):
        fname = path / image_fname(url, i + 1, offset, settings["no_num_images"])
        if not image_writable(fname, settings["force"]):
            continue
        images.append((fname, url))

    threads = settings["threads"]
    if threads > 1 and len(images) > 0:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            list(
                executor.map(
                    lambda x: get_image(x[0], hdpo, x[1]),
                    images,
                )
            )
    else:
        for fname, url in images:
            get_image(fname, hdpo, url)


def write_info(path: Path, info: dict | list[dict], force: bool):
    ipath = path / "info.json"
    if path_writable_file(ipath, force) is False:
        return
    with open(ipath, "w") as f:
        json.dump(info, f)


def get_comments(hdpo: hdporncomics, c_id: int, limit: int) -> list:
    comments = []
    if c_id == 0:
        return comments
    page = 1
    for i in hdpo.get_comments(c_id):
        comments += i["comments"]

        if page != -1 and page >= limit:
            break
        page += 1

    return comments


def write_comiclike_info(
    path: Path, hdpo: hdporncomics, comic: dict, settings: dict, comments: bool = True
):
    if settings["images_only"]:
        return

    climit = settings["comment_limit"]
    if comments and climit != 0:
        comic["comments"] = get_comments(hdpo, comic["id"], climit)

    write_info(path, comic, True)


def get_comiclike(
    path: Path,
    hdpo: hdporncomics,
    url: str,
    func: Callable,
    funcnext: Callable,
    settings: dict,
    comments: bool = True,
):
    r = func(url)
    dname = path / escape_path(r["title"])

    d = path_writable_dir(dname, settings["force"])
    if d is False:
        return
    if d is True:
        os.mkdir(dname)

    write_comiclike_info(dname, hdpo, r, settings, comments=comments)

    funcnext(dname, hdpo, r, settings)


def get_comic_images(path: Path, hdpo: hdporncomics, info: dict, settings: dict):
    get_images(path, hdpo, info["images"], settings)


def get_manhwa_chapters(path: Path, hdpo: hdporncomics, info: dict, settings: dict):
    if settings["nochapters"]:
        return
    for i in info["chapters"]:
        chapter(path, hdpo, i["link"], settings)


def chapter(path: Path, hdpo: hdporncomics, url: str, settings: dict):
    get_comiclike(
        path,
        hdpo,
        url,
        hdpo.get_manhwa_chapter,
        get_comic_images,
        settings,
        comments=False,
    )


def manhwa(path: Path, hdpo: hdporncomics, url: str, settings: dict):
    get_comiclike(path, hdpo, url, hdpo.get_manhwa, get_manhwa_chapters, settings)


def comic(path: Path, hdpo: hdporncomics, url: str, settings: dict):
    get_comiclike(path, hdpo, url, hdpo.get_comic, get_comic_images, settings)


def pages(path: Path, hdpo: hdporncomics, url: str, settings: dict):
    page = 1
    plimit = settings["pages_max"]
    if plimit == 0:
        return

    posts = []

    for i in hdpo.get_pages(url):
        for j in i["posts"]:
            guess(path, hdpo, j["link"], settings)

            posts.append(j)

        if plimit != -1 and page >= plimit:
            break
        page += 1

    if not settings["images_only"]:
        write_info(path, posts, settings["force"])


def cli(argv: list[str]):
    args = argparser().parse_args(argv)

    if args.images_only and args.noimages:
        raise Exception("Nothing to do")

    osettings = {
        "threads": args.threads,
        "force": args.force,
        "no_num_images": args.no_num_images,
        "images_only": args.images_only,
        "noimages": args.noimages,
        "nochapters": args.nochapters,
        "comment_limit": args.comment_limit,
        "pages_max": args.pages_max,
    }

    hdpo = hdporncomics(logger=treerequests.simple_logger(sys.stdout))
    treerequests.args_session(hdpo.ses, args)
    path = Path(".")

    for url in args.urls:
        guess(path, hdpo, url, osettings)
    for url in args.chapter:
        chapter(path, hdpo, url, osettings)
    for url in args.manhwa:
        manhwa(path, hdpo, url, osettings)
    for url in args.comic:
        comic(path, hdpo, url, osettings)
    for url in args.pages:
        pages(path, hdpo, url, osettings)
