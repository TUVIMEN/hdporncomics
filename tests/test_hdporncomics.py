#!/usr/bin/env python
# by Dominik Stanisław Suchora <hexderm@gmail.com>
# License: GNU GPLv3

import sys
import os
import re
from datetime import datetime
import json

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/.."))

from biggusdictus import *
from hdporncomics import hdporncomics

hdpo = hdporncomics(wait=1.5)

hdpol = hdporncomics(wait=1.5)
# tests require that this account has some things viewed, liked, commented, subscribed, etc.
hdpol.login(os.environ["HDPORNCOMICS_EMAIL"], os.environ["HDPORNCOMICS_PASSWORD"])


def OptUrl(w):
    return Or(w, Url, isstr, isNone)


sche = Scheme()


def check(data, *args):
    sche.dict(data, *args)


def test_get_stats():
    r = hdpo.get_stats()

    check(
        r,
        ("comics", int, 1),
        ("gay", int, 1),
        ("manhwa", int, 1),
        ("artists", int, 1),
        ("categories", int, 1),
        ("characters", int, 1),
        ("groups", int, 1),
        ("parodies", int, 1),
        ("tags", int, 1),
        ("comments", int, 1),
        ("users", int, 1),
        ("moderators", int, 1),
        (
            "most_active_users",
            list,
            (
                dict,
                ("avatar", OptUrl),
                ("link", Url),
                ("user", str, 1),
            ),
            1,
        ),
    )


def check_comment(c):
    check(
        c,
        ("id", int, 1),
        ("user", str, 1),
        ("userid", int),
        ("avatar", OptUrl),
        ("content", str),
        ("likes", int),
        ("posted", Isodate),
        ("children", list, check_comment),
    )


def check_comments_page(c):
    check(
        c,
        ("comments", list, check_comment, 1),
        ("page", int, 1),
        ("nexturl", OptUrl),
    )


def test_get_comments():
    for i in hdpo.get_comments(83389, top=True):
        check_comments_page(i)

        isint(len(i["comments"]), 25)
        break


def check_comic(c):
    check(
        c,
        ("cover", Url),
        ("title", str, 1),
        ("tags", list, (str, 1)),
        ("artists", list, (str, 1)),
        ("categories", list, (str, 1)),
        ("groups", list, (str, 1)),
        ("genres", list, (str, 1)),
        ("sections", list, (str, 1)),
        ("languages", list, (str, 1)),
        ("characters", list, (str, 1)),
        ("images_count", int),
        ("published", Isodate),
        ("modified", Isodate),
        ("id", int, 1),
        ("images", list, Url, 1),
        (
            "related",
            list,
            (
                dict,
                ("name", str, 1),
                (
                    "items",
                    list,
                    (dict, ("cover", Url), ("title", str, 1), ("link", Url)),
                ),
            ),
        ),
        ("comments_count", int),
        ("url", Url),
        ("likes", int),
        ("dlikes", int),
        ("views", int, 1),
        ("favorites", int),
        ("comments", list, check_comment),
        ("comments_pages", int),
    )


def test_get_comic1():
    r = hdpo.get_comic("https://hdporncomics.com/two-princesses-one-yoshi-sex-comic/")
    check_comic(r)
    isint(r["views"], 50000)
    isint(len(r["tags"]), 3)
    isint(len(r["categories"]), 3)
    isint(len(r["images"]), 8)
    isint(r["images_count"], 8)
    isint(r["comments_count"], 3)
    isstr(r["title"], 22)
    isint(len(r["related"]), 3)


def test_get_comic2():
    r = hdpo.get_comic(
        "https://hdporncomics.com/summer-vacation-with-bakugo-s-mom-part-three-chapter-two-nonconsent-reluctance-netorare-cheating-mature-superheroes-tv-movies-sex-comic/"
    )
    check_comic(r)
    assert len(r["artists"]) == 1
    assert len(r["groups"]) == 2
    isint(len(r["tags"]), 9)
    isint(len(r["characters"]), 2)


def test_get_comic3():
    r = hdpo.get_comic(
        "https://hdporncomics.com/gay-manga/shadbase-hit-or-miss-me-with-that-gay-shit-eng-gay-manga/",
        comments=2,
    )
    check_comic(r)
    assert len(r["sections"]) == 1
    isint(len(r["groups"]), 5)
    assert len(r["languages"]) == 1
    assert len(r["genres"]) == 1
    assert len(r["comments"]) == 50


def check_manhwa(c):
    check(
        c,
        ("cover", Url),
        ("title", str, 1),
        ("artists", list, (str, 1)),
        ("authors", list, (str, 1)),
        ("genres", list, (str, 1)),
        ("altname", str, 1),
        ("status", str, 1),
        ("modified", Isodate),
        ("published", Isodate),
        ("id", int, 1),
        ("comments_count", int),
        ("summary", str, 1),
        (
            "chapters",
            list,
            (
                dict,
                ("link", Url),
                ("name", str, 1),
                ("date", Isodate),
            ),
            1,
        ),
        ("url", Url),
        ("likes", int),
        ("dlikes", int),
        ("views", int, 1),
        ("favorites", int),
        ("comments", list, check_comment),
        ("comments_pages", int),
    )


def test_get_manhwa():
    r = hdpo.get_manhwa(
        "https://hdporncomics.com/manhwa/my-stepmom-manhwa-porn/",
        comments=2,
    )
    check_manhwa(r)
    assert len(r["chapters"]) == 52
    assert len(r["artists"]) == 1
    assert len(r["authors"]) == 1
    isint(len(r["genres"]), 6)
    isint(r["views"], 400000)
    isint(r["comments_count"], 38)
    isint(
        len(r["comments"]), 25
    )  # for some reason site does not allow to get more than first page


def check_manhwa_chapter(c):
    check(
        c,
        ("id", int, 1),
        ("title", str, 1),
        ("manhwa", dict, ("link", Url), ("title", str, 1), ("id", int, 1)),
        ("images", list, str, 1),
        ("comments_count", int),
        ("url", Url),
        ("modified", Isodate),
        ("published", Isodate),
        ("comments", list, check_comment),
        ("comments_pages", int),
    )


def test_get_manhwa_chapter():
    r = hdpo.get_manhwa_chapter(
        "https://hdporncomics.com/manhwa/my-stepmom-manhwa-porn/chapter-50/",
        comments=2,
    )
    check_manhwa_chapter(r)
    isint(len(r["comments"]), 25)
    assert len(r["images"]) == 159


def check_page(c, manhwa):
    check(
        c,
        ("url", Url),
        ("nexturl", OptUrl),
        ("page", int),
        ("lastpage", int),
        ("term_id", int),
        (
            "posts",
            list,
            (
                dict,
                ("id", int, 1),
                ("cover", Url),
                ("date", Isodate),
                ("link", Url),
                ("title", str, 1),
                ("views", int),
                ("images", int, (0 if manhwa else 1)),
                ("likes", int),
                ("dlikes", int),
                ("tags", list, (str, 1)),
                (
                    "chapters",
                    list,
                    (
                        dict,
                        ("link", Url),
                        ("title", str, 1),
                        ("date", Isodate),
                    ),
                ),
            ),
            1,
        ),
    )


def check_pages(pages, maxpages=2, manhwa=False):
    page = 1
    for i in pages:
        check_page(i, manhwa)
        yield i

        if page >= maxpages:
            break
        page += 1


def test_get_new():
    for i in check_pages(hdpo.get_new()):
        isint(i["lastpage"], 3000)


def test_get_gay():
    for i in check_pages(hdpo.get_gay()):
        isint(i["lastpage"], 1800)


def test_get_manhwas():
    for i in check_pages(hdpo.get_manhwas(), manhwa=True):
        isint(i["lastpage"], 70)


def test_get_comic_series():
    for i in check_pages(hdpo.get_new()):
        isint(i["lastpage"], 100)


def test_search():
    for i in check_pages(hdpo.search("not")):
        isint(i["lastpage"], 20)


def test_get_pages_tag():
    for i in check_pages(hdpo.get_pages("https://hdporncomics.com/tag/spanking/")):
        isint(i["lastpage"], 40)
        isint(i["term_id"], 1100)


def test_get_user():
    r = hdpo.get_user(
        "https://hdporncomics.com/author/yuri-lover/",
    )

    check(
        r,
        ("url", Url),
        ("id", int, 1),
        ("name", str, 1),
        ("joined", Isodate),
        ("lastseen", Isodate),
        ("comments", int),
    )

    isint(r["comments"], 3200)


def check_terms(c):
    sche.list(c, (dict, ("name", str, 1), ("id", int, 1)), 1)


def test_get_terms_artist():
    r = hdpo.get_terms("artist")
    check_terms(r)
    isint(len(r), 14000)


def test_get_terms_parody():
    r = hdpo.get_terms("parody")
    check_terms(r)
    isint(len(r), 1150)


def test_get_terms_tags():
    r = hdpo.get_terms("tags")
    check_terms(r)
    isint(len(r), 1400)


def test_get_terms_groups():
    r = hdpo.get_terms("groups")
    check_terms(r)
    isint(len(r), 2600)


def test_get_terms_characters():
    r = hdpo.get_terms("characters")
    check_terms(r)
    isint(len(r), 6900)


def test_get_terms_category():
    r = hdpo.get_terms("category")
    check_terms(r)
    isint(len(r), 12)


def check_gay_or_manhwa_list(c):
    check(
        c,
        ("id", int, 1),
        (
            "list",
            list,
            (dict, ("link", Url), ("name", str), ("count", int)),
            1,
        ),
    )


def test_get_manhwa_artists_list():
    r = hdpo.get_manhwa_artists_list()
    check_gay_or_manhwa_list(r)
    isint(len(r["list"]), 1200)


def test_get_manhwa_authors_list():
    r = hdpo.get_manhwa_authors_list()
    check_gay_or_manhwa_list(r)
    isint(len(r["list"]), 1200)


def test_get_manhwa_genres_list():
    r = hdpo.get_manhwa_genres_list()
    check_gay_or_manhwa_list(r)
    isint(len(r["list"]), 50)


def test_get_gay_genres_list():
    r = hdpo.get_gay_genres_list()
    check_gay_or_manhwa_list(r)
    isint(len(r["list"]), 25)


def test_get_gay_groups_list():
    r = hdpo.get_gay_groups_list()
    check_gay_or_manhwa_list(r)
    isint(len(r["list"]), 1)


def test_get_gay_languages_list():
    r = hdpo.get_gay_languages_list()
    check_gay_or_manhwa_list(r)
    isint(len(r["list"]), 20)


def test_get_gay_sections_list():
    r = hdpo.get_gay_sections_list()
    check_gay_or_manhwa_list(r)
    isint(len(r["list"]), 500)


def check_comics_list(c):
    check(
        c,
        ("url", Url),
        ("nexturl", OptUrl),
        ("page", int),
        ("lastpage", int),
        (
            "posts",
            list,
            (
                dict,
                ("cover", Url),
                ("link", Url),
                ("name", str, 1),
                ("count", int, 1),
            ),
            1,
        ),
    )


def test_get_comics_list_parodies():
    page = 1
    for i in hdpo.get_comics_list(
        "parodies",
        page=2,
        sort="likes",
    ):
        check_comics_list(i)
        isint(i["lastpage"], 50)
        if page >= 2:
            break
        page += 1


def test_get_comics_list_artists():
    page = 1
    for i in hdpo.get_comics_list(
        "artists",
        page=2,
        sort="favorites",
    ):
        check_comics_list(i)
        isint(i["lastpage"], 670)
        if page >= 2:
            break
        page += 1


def test_get_comics_list_groups():
    page = 1
    for i in hdpo.get_comics_list(
        "groups",
        page=2,
        sort="count",
    ):
        check_comics_list(i)
        isint(i["lastpage"], 125)
        if page >= 2:
            break
        page += 1


def test_get_comics_list_categories():
    page = 1
    for i in hdpo.get_comics_list(
        "categories",
    ):
        check_comics_list(i)
        int(i["lastpage"])
        if page >= 2:
            break
        page += 1


def test_get_comics_list_tags():
    page = 1
    for i in hdpo.get_comics_list(
        "tags",
        page=2,
    ):
        check_comics_list(i)
        isint(i["lastpage"], 12)
        if page >= 2:
            break
        page += 1


def test_get_comics_list_characters():
    page = 1
    for i in hdpo.get_comics_list(
        "characters",
        page=2,
    ):
        check_comics_list(i)
        isint(i["lastpage"], 320)
        if page >= 2:
            break
        page += 1


def test_get_comics_list_search():
    page = 1
    for i in hdpo.get_comics_list("characters", page=2, search="the"):
        check_comics_list(i)
        isint(i["lastpage"], 5)
        if page >= 2:
            break
        page += 1


def test_guess():
    assert (
        hdpo.guess("https://hdporncomics.com/comics/artists/")
        == hdpo.get_comics_list_url
    )


##################


def test_get_dashboard_stats():
    r = hdpol.get_dashboard_stats()
    check(
        r,
        ("likes", int, 1),
        ("favorites", int, 1),
        ("history", int, 1),
        ("comments", int, 1),
    )


def check_history_page(c):
    check(
        c,
        ("url", Url),
        ("nexturl", OptUrl),
        ("page", int),
        ("lastpage", int),
        (
            "posts",
            list,
            (
                dict,
                ("type", str, 1),
                ("id", int),
                ("title", str, 1),
                ("link", Url),
                ("cover", Url),
                ("views", int),
                ("likes", int),
                ("dlikes", int),
                ("favorites", int),
                ("comments", int),
                ("created", Isodate),
                ("modified", Isodate),
            ),
            1,
        ),
    )


def test_get_history():
    page = 1
    for i in hdpol.get_history():
        check_history_page(i)

        if page >= 2:
            break
        page += 1


def test_get_liked():
    page = 1
    for i in hdpol.get_liked():
        check_history_page(i)

        if page >= 2:
            break
        page += 1


def test_get_favorites():
    page = 1
    for i in hdpol.get_favorites():
        check_history_page(i)

        if page >= 2:
            break
        page += 1


def check_subscriptions(c):
    sche.list(
        c,
        (
            dict,
            ("id", int),
            ("name", str, 1),
            ("count", int),
            ("link", Url),
        ),
        1,
    )


def test_get_subscriptions():
    r = hdpol.get_subscriptions()
    check_subscriptions(r)


def check_user_comments_page(c):
    check(
        c,
        ("url", Url),
        ("nexturl", OptUrl),
        ("page", int),
        ("lastpage", int),
        (
            "posts",
            list,
            (
                dict,
                ("id", int),
                ("comic_id", int),
                ("comic_link", Url),
                ("user", str, 1),
                ("userid", int),
                ("content", str, 1),
                ("parent", int),
                ("date", Isodate),
                ("likes", int),
                ("replies", int),
                ("avatar", OptUrl),
            ),
            1,
        ),
    )


def test_get_user_comments():
    page = 1
    for i in hdpol.get_user_comments():
        check_user_comments_page(i)

        if page >= 2:
            break
        page += 1


def test_like():
    hdpol.like(215995, False)

    assert hdpol.like(215995) is True
    for i in hdpol.get_liked():
        check_history_page(i)
        assert i["posts"][0]["id"] == 215995
        break

    hdpol.like(215995, False)


def test_like_delete():
    hdpol.like(215995, True)

    assert hdpol.like(215995, False) is True
    for i in hdpol.get_liked():
        check_history_page(i)
        assert i["posts"][0]["id"] != 215995
        break


def test_favorite():
    hdpol.favorite(215995, False)

    assert hdpol.favorite(215995) is True
    for i in hdpol.get_favorites():
        check_history_page(i)
        assert i["posts"][0]["id"] == 215995
        break

    hdpol.favorite(215995, False)


def test_favorite_delete():
    hdpol.favorite(215995, True)

    assert hdpol.favorite(215995, False) is True
    for i in hdpol.get_favorites():
        check_history_page(i)
        assert i["posts"][0]["id"] != 215995
        break


def test_history():
    hdpol.view(215995, False)

    assert hdpol.view(215995) is True
    for i in hdpol.get_history():
        check_history_page(i)
        assert i["posts"][0]["id"] == 215995
        break

    hdpol.view(215995, False)


def test_history_delete():
    hdpol.view(215995, True)

    assert hdpol.view(215995, False) is True
    for i in hdpol.get_history():
        check_history_page(i)
        assert i["posts"][0]["id"] != 215995
        break


def test_subscribe():
    hdpol.subscribe(69656, False)

    assert hdpol.subscribe(69656) is True
    r = hdpol.get_subscriptions()
    check_subscriptions(r)
    assert r[0]["id"] == 69656

    hdpol.subscribe(69656, False)


def test_subscribe_delete():
    hdpol.subscribe(69656, True)

    assert hdpol.subscribe(69656, False) is True
    r = hdpol.get_subscriptions()
    check_subscriptions(r)
    assert r[0]["id"] != 69656


def check_notifications_page(c):
    check(
        c,
        ("url", Url),
        ("nexturl", OptUrl),
        ("page", int),
        ("lastpage", int),
        (
            "notifications",
            list,
            (
                dict,
                ("title", str, 1),
                ("link", Url),
                ("type", str, 1),
                ("date", Isodate),
                ("id", str, 1),
            ),
        ),
    )


def test_comment():
    msg = "Atlantis Ascendant"
    assert hdpol.comment(215999, msg) is True

    c_id = 0
    for i in hdpol.get_comments(215999):
        check_comments_page(i)
        c = i["comments"]
        isint(len(c), 1)
        assert c[0]["content"] == msg
        assert c[0]["likes"] == 0
        c_id = c[0]["id"]
        break

    assert hdpol.comment_like(c_id) is True

    for i in hdpol.get_comments(215999):
        check_comments_page(i)
        isint(len(c), 1)
        c = i["comments"]
        assert c[0]["id"] == c_id
        assert c[0]["likes"] == 1
        break

    assert hdpol.comment_like(c_id, False) is True

    for i in hdpol.get_comments(215999):
        check_comments_page(i)
        isint(len(c), 1)
        c = i["comments"]
        assert c[0]["id"] == c_id
        assert c[0]["likes"] == 0
        break

    assert hdpol.comment_delete(c_id) is True

    for i in hdpol.get_comments(215999):
        check_comments_page(i)
        c = i["comments"]
        assert c[0]["id"] != c_id


def test_get_notifications():
    assert hdpol.notifications_clean() is True

    msg = "Draconis Albionensis"
    assert hdpol.comment(188936, msg) is True

    c_id = 0
    for i in hdpol.get_comments(188936):
        check_comments_page(i)
        c = i["comments"]
        isint(len(c), 1)
        assert c[0]["content"] == msg
        assert c[0]["likes"] == 0
        c_id = c[0]["id"]
        break

    msg2 = "The Splendour Of A Thousand Swords Gleaming Beneath The Blazon Of The Hyperborean Empire"
    hdpol.comment(
        188936,
        msg2,
        parent=c_id,
    )

    c2_id = 0
    for i in hdpol.get_comments(188936):
        check_comments_page(i)
        isint(len(c), 1)
        c = i["comments"]
        assert c[0]["id"] == c_id

        ch = c[0]["children"]
        isint(len(ch), 1)
        assert ch[0]["content"] == msg2
        c2_id = ch[0]["id"]
        break

    for i in hdpol.get_notifications():
        check_notifications_page(i)
        isint(len(i["notifications"]), 1)
        break

    assert hdpol.notifications_clean() is True

    for i in hdpol.get_notifications():
        check_notifications_page(i)
        assert len(i["notifications"]) == 0
        break

    assert hdpol.comment_delete(c2_id) is True
    assert hdpol.comment_delete(c_id) is True
