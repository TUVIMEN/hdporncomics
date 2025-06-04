#!/usr/bin/env python
# by Dominik Stanisław Suchora <hexderm@gmail.com>
# License: GNU GPLv3

import sys
import os
import re
from datetime import datetime
import json

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/.."))
from hdporncomics import hdporncomics

hdpo = hdporncomics(wait=1.5)

hdpol = hdporncomics(wait=1.5)
# tests require that this account has some things viewed, liked, commented, subscribed, etc.
hdpol.login(os.environ["HDPORNCOMICS_EMAIL"], os.environ["HDPORNCOMICS_PASSWORD"])


def inrange(w, x=0, y=9999999999):
    assert isinstance(w, int)
    assert w >= x and w <= y


def isstr(w, x=1, y=9999999999):
    assert isinstance(w, str)
    inrange(len(w.strip()), x, y)


def isisodate(d):
    isstr(d)
    try:
        datetime.fromisoformat(d)
    except:
        assert 0


def urlvalid(url):
    isstr(url)
    r = re.match(r"^https?://([a-z0-9A-Z_-]+\.)+[a-zA-Z]+(/|\?|$)", url)
    assert r is not None


def opturlvalid(url):
    if url is None:
        return

    if url == "":
        return

    urlvalid(url)


def islist(w, checker, x=-1, y=999999999):
    assert isinstance(w, list)
    if x != -1:
        inrange(len(w), x, y)
    if checker is not None:
        for i in w:
            checker(i)


def checkdict_checkers(check):
    for i in check:
        assert len(i) >= 2


def checkdict(d, *check):
    assert isinstance(d, dict)
    checkdict_checkers(check)

    keys = d.keys()
    assert len(check) == len(keys)

    for i in keys:
        found = 0
        for j in check:
            if i == j[0]:
                j[1](d[i], *j[2:])
                found = 1
                break

        if found == 0:
            raise Exception("Dictionary key isn't handled")


def test_get_stats():
    r = hdpo.get_stats()

    checkdict(
        r,
        ("comics", inrange, 1),
        ("gay", inrange, 1),
        ("manhwa", inrange, 1),
        ("artists", inrange, 1),
        ("categories", inrange, 1),
        ("characters", inrange, 1),
        ("groups", inrange, 1),
        ("parodies", inrange, 1),
        ("tags", inrange, 1),
        ("comments", inrange, 1),
        ("users", inrange, 1),
        ("moderators", inrange, 1),
        (
            "most_active_users",
            islist,
            lambda x: checkdict(
                x,
                ("avatar", opturlvalid),
                ("link", urlvalid),
                ("user", isstr),
            ),
            1,
        ),
    )


def check_comment(c):
    checkdict(
        c,
        ("id", inrange, 1),
        ("user", isstr),
        ("userid", inrange),
        ("avatar", opturlvalid),
        ("content", isstr, 0),
        ("likes", inrange),
        ("posted", isisodate),
        ("children", islist, check_comment),
    )


def check_comments_page(c):
    checkdict(
        c,
        ("comments", islist, check_comment, 1),
        ("page", inrange, 1),
        ("nexturl", opturlvalid),
    )


def test_get_comments():
    for i in hdpo.get_comments(83389, top=True):
        check_comments_page(i)

        inrange(len(i["comments"]), 25)
        break


def check_comic(c):
    checkdict(
        c,
        ("cover", urlvalid),
        ("title", isstr),
        ("tags", islist, isstr),
        ("artists", islist, isstr),
        ("categories", islist, isstr),
        ("groups", islist, isstr),
        ("genres", islist, isstr),
        ("sections", islist, isstr),
        ("languages", islist, isstr),
        ("characters", islist, isstr),
        ("images_count", inrange),
        ("published", isisodate),
        ("modified", isisodate),
        ("id", inrange, 1),
        ("images", islist, urlvalid, 1),
        (
            "related",
            islist,
            lambda x: checkdict(
                x,
                ("name", isstr),
                (
                    "items",
                    islist,
                    lambda x: checkdict(
                        x, ("cover", urlvalid), ("title", isstr), ("link", urlvalid)
                    ),
                ),
            ),
        ),
        ("comments_count", inrange),
        ("url", urlvalid),
        ("likes", inrange),
        ("dlikes", inrange),
        ("views", inrange, 1),
        ("favorites", inrange),
        ("comments", islist, check_comment),
        ("comments_pages", inrange),
    )


def test_get_comic1():
    r = hdpo.get_comic("https://hdporncomics.com/two-princesses-one-yoshi-sex-comic/")
    check_comic(r)
    inrange(r["views"], 50000)
    inrange(len(r["tags"]), 3)
    inrange(len(r["categories"]), 3)
    inrange(len(r["images"]), 8)
    inrange(r["images_count"], 8)
    inrange(r["comments_count"], 3)
    isstr(r["title"], 22)
    inrange(len(r["related"]), 3)


def test_get_comic2():
    r = hdpo.get_comic(
        "https://hdporncomics.com/summer-vacation-with-bakugo-s-mom-part-three-chapter-two-nonconsent-reluctance-netorare-cheating-mature-superheroes-tv-movies-sex-comic/"
    )
    check_comic(r)
    assert len(r["artists"]) == 1
    assert len(r["groups"]) == 2
    inrange(len(r["tags"]), 9)
    inrange(len(r["characters"]), 2)


def test_get_comic3():
    r = hdpo.get_comic(
        "https://hdporncomics.com/gay-manga/shadbase-hit-or-miss-me-with-that-gay-shit-eng-gay-manga/",
        comments=2,
    )
    check_comic(r)
    assert len(r["sections"]) == 1
    inrange(len(r["groups"]), 5)
    assert len(r["languages"]) == 1
    assert len(r["genres"]) == 1
    assert len(r["comments"]) == 50


def check_manhwa(c):
    checkdict(
        c,
        ("cover", urlvalid),
        ("title", isstr),
        ("artists", islist, isstr),
        ("authors", islist, isstr),
        ("genres", islist, isstr),
        ("altname", isstr),
        ("status", isstr),
        ("modified", isisodate),
        ("published", isisodate),
        ("id", inrange, 1),
        ("comments_count", inrange),
        ("summary", isstr),
        (
            "chapters",
            islist,
            lambda x: checkdict(
                x,
                ("link", urlvalid),
                ("name", isstr),
                ("date", isisodate),
            ),
            1,
        ),
        ("url", urlvalid),
        ("likes", inrange),
        ("dlikes", inrange),
        ("views", inrange, 1),
        ("favorites", inrange),
        ("comments", islist, check_comment),
        ("comments_pages", inrange),
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
    inrange(len(r["genres"]), 6)
    inrange(r["views"], 400000)
    inrange(r["comments_count"], 38)
    inrange(
        len(r["comments"]), 25
    )  # for some reason site does not allow to get more than first page


def check_manhwa_chapter(c):
    checkdict(
        c,
        ("id", inrange, 1),
        ("title", isstr),
        (
            "manhwa",
            lambda x: checkdict(
                x, ("link", urlvalid), ("title", isstr), ("id", inrange, 1)
            ),
        ),
        ("images", islist, isstr, 1),
        ("comments_count", inrange),
        ("url", urlvalid),
        ("modified", isisodate),
        ("published", isisodate),
        ("comments", islist, check_comment),
        ("comments_pages", inrange),
    )


def test_get_manhwa_chapter():
    r = hdpo.get_manhwa_chapter(
        "https://hdporncomics.com/manhwa/my-stepmom-manhwa-porn/chapter-50/",
        comments=2,
    )
    check_manhwa_chapter(r)
    inrange(len(r["comments"]), 25)
    assert len(r["images"]) == 159


def check_page(c, manhwa):
    checkdict(
        c,
        ("url", urlvalid),
        ("nexturl", opturlvalid),
        ("page", inrange),
        ("lastpage", inrange),
        ("term_id", inrange),
        (
            "posts",
            islist,
            lambda x: checkdict(
                x,
                ("id", inrange, 1),
                ("cover", urlvalid),
                ("date", isisodate),
                ("link", urlvalid),
                ("title", isstr),
                ("views", inrange),
                ("images", inrange, (0 if manhwa else 1)),
                ("likes", inrange),
                ("dlikes", inrange),
                ("tags", islist, isstr),
                (
                    "chapters",
                    islist,
                    lambda y: checkdict(
                        y,
                        ("link", urlvalid),
                        ("title", isstr),
                        ("date", isisodate),
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
        inrange(i["lastpage"], 3000)


def test_get_gay():
    for i in check_pages(hdpo.get_gay()):
        inrange(i["lastpage"], 1800)


def test_get_manhwas():
    for i in check_pages(hdpo.get_manhwas(), manhwa=True):
        inrange(i["lastpage"], 70)


def test_get_comic_series():
    for i in check_pages(hdpo.get_new()):
        inrange(i["lastpage"], 100)


def test_search():
    for i in check_pages(hdpo.search("not")):
        inrange(i["lastpage"], 20)


def test_get_pages_tag():
    for i in check_pages(hdpo.get_pages("https://hdporncomics.com/tag/spanking/")):
        inrange(i["lastpage"], 40)
        inrange(i["term_id"], 1100)


def test_get_user():
    r = hdpo.get_user(
        "https://hdporncomics.com/author/yuri-lover/",
    )

    checkdict(
        r,
        ("url", urlvalid),
        ("id", inrange, 1),
        ("name", isstr),
        ("joined", isisodate),
        ("lastseen", isisodate),
        ("comments", inrange),
    )

    inrange(r["comments"], 3200)


def check_terms(c):
    islist(c, lambda x: checkdict(x, ("name", isstr), ("id", inrange, 1)), 1)


def test_get_terms_artist():
    r = hdpo.get_terms("artist")
    check_terms(r)
    inrange(len(r), 14000)


def test_get_terms_parody():
    r = hdpo.get_terms("parody")
    check_terms(r)
    inrange(len(r), 1150)


def test_get_terms_tags():
    r = hdpo.get_terms("tags")
    check_terms(r)
    inrange(len(r), 1400)


def test_get_terms_groups():
    r = hdpo.get_terms("groups")
    check_terms(r)
    inrange(len(r), 2600)


def test_get_terms_characters():
    r = hdpo.get_terms("characters")
    check_terms(r)
    inrange(len(r), 6900)


def test_get_terms_category():
    r = hdpo.get_terms("category")
    check_terms(r)
    inrange(len(r), 12)


def check_gay_or_manhwa_list(c):
    checkdict(
        c,
        ("id", inrange, 1),
        (
            "list",
            islist,
            lambda x: checkdict(
                x, ("link", urlvalid), ("name", isstr, 0), ("count", inrange)
            ),
            1,
        ),
    )


def test_get_manhwa_artists_list():
    r = hdpo.get_manhwa_artists_list()
    check_gay_or_manhwa_list(r)
    inrange(len(r["list"]), 1200)


def test_get_manhwa_authors_list():
    r = hdpo.get_manhwa_authors_list()
    check_gay_or_manhwa_list(r)
    inrange(len(r["list"]), 1200)


def test_get_manhwa_genres_list():
    r = hdpo.get_manhwa_genres_list()
    check_gay_or_manhwa_list(r)
    inrange(len(r["list"]), 50)


def test_get_gay_genres_list():
    r = hdpo.get_gay_genres_list()
    check_gay_or_manhwa_list(r)
    inrange(len(r["list"]), 25)


def test_get_gay_groups_list():
    r = hdpo.get_gay_groups_list()
    check_gay_or_manhwa_list(r)
    inrange(len(r["list"]), 1)


def test_get_gay_languages_list():
    r = hdpo.get_gay_languages_list()
    check_gay_or_manhwa_list(r)
    inrange(len(r["list"]), 20)


def test_get_gay_sections_list():
    r = hdpo.get_gay_sections_list()
    check_gay_or_manhwa_list(r)
    inrange(len(r["list"]), 500)


def check_comics_list(c):
    checkdict(
        c,
        ("url", urlvalid),
        ("nexturl", opturlvalid),
        ("page", inrange),
        ("lastpage", inrange),
        (
            "posts",
            islist,
            lambda x: checkdict(
                x,
                ("cover", urlvalid),
                ("link", urlvalid),
                ("name", isstr),
                ("count", inrange, 1),
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
        inrange(i["lastpage"], 50)
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
        inrange(i["lastpage"], 670)
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
        inrange(i["lastpage"], 125)
        if page >= 2:
            break
        page += 1


def test_get_comics_list_categories():
    page = 1
    for i in hdpo.get_comics_list(
        "categories",
    ):
        check_comics_list(i)
        inrange(i["lastpage"])
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
        inrange(i["lastpage"], 12)
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
        inrange(i["lastpage"], 320)
        if page >= 2:
            break
        page += 1


def test_get_comics_list_search():
    page = 1
    for i in hdpo.get_comics_list("characters", page=2, search="the"):
        check_comics_list(i)
        inrange(i["lastpage"], 5)
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
    checkdict(
        r,
        ("likes", inrange, 1),
        ("favorites", inrange, 1),
        ("history", inrange, 1),
        ("comments", inrange, 1),
    )


def check_history_page(c):
    checkdict(
        c,
        ("url", urlvalid),
        ("nexturl", opturlvalid),
        ("page", inrange),
        ("lastpage", inrange),
        (
            "posts",
            islist,
            lambda x: checkdict(
                x,
                ("type", isstr),
                ("id", inrange),
                ("title", isstr),
                ("link", urlvalid),
                ("cover", urlvalid),
                ("views", inrange),
                ("likes", inrange),
                ("dlikes", inrange),
                ("favorites", inrange),
                ("comments", inrange),
                ("created", isisodate),
                ("modified", isisodate),
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
    islist(
        c,
        lambda x: checkdict(
            x,
            ("id", inrange),
            ("name", isstr),
            ("count", inrange),
            ("link", urlvalid),
        ),
        1,
    )


def test_get_subscriptions():
    r = hdpol.get_subscriptions()
    check_subscriptions(r)


def check_user_comments_page(c):
    checkdict(
        c,
        ("url", urlvalid),
        ("nexturl", opturlvalid),
        ("page", inrange),
        ("lastpage", inrange),
        (
            "posts",
            islist,
            lambda x: checkdict(
                x,
                ("id", inrange),
                ("comic_id", inrange),
                ("comic_link", urlvalid),
                ("user", isstr),
                ("userid", inrange),
                ("content", isstr),
                ("parent", inrange),
                ("date", isisodate),
                ("likes", inrange),
                ("replies", inrange),
                ("avatar", opturlvalid),
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
    checkdict(
        c,
        ("url", urlvalid),
        ("nexturl", opturlvalid),
        ("page", inrange),
        ("lastpage", inrange),
        (
            "notifications",
            islist,
            lambda x: checkdict(
                x,
                ("title", isstr),
                ("link", urlvalid),
                ("type", isstr),
                ("date", isisodate),
                ("id", isstr),
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
        inrange(len(c), 1)
        assert c[0]["content"] == msg
        assert c[0]["likes"] == 0
        c_id = c[0]["id"]
        break

    assert hdpol.comment_like(c_id) is True

    for i in hdpol.get_comments(215999):
        check_comments_page(i)
        inrange(len(c), 1)
        c = i["comments"]
        assert c[0]["id"] == c_id
        assert c[0]["likes"] == 1
        break

    assert hdpol.comment_like(c_id, False) is True

    for i in hdpol.get_comments(215999):
        check_comments_page(i)
        inrange(len(c), 1)
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
        inrange(len(c), 1)
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
        inrange(len(c), 1)
        c = i["comments"]
        assert c[0]["id"] == c_id

        ch = c[0]["children"]
        inrange(len(ch), 1)
        assert ch[0]["content"] == msg2
        c2_id = ch[0]["id"]
        break

    for i in hdpol.get_notifications():
        check_notifications_page(i)
        inrange(len(i["notifications"]), 1)
        break

    assert hdpol.notifications_clean() is True

    for i in hdpol.get_notifications():
        check_notifications_page(i)
        assert len(i["notifications"]) == 0
        break

    assert hdpol.comment_delete(c2_id) is True
    assert hdpol.comment_delete(c_id) is True
