#!/usr/bin/env python
# by Dominik Stanisław Suchora <hexderm@gmail.com>
# License: GNU GPLv3

import time
import random
import hashlib
import os
import re
import json
import base64
from datetime import datetime
from typing import Optional, Tuple, Generator, Callable

import treerequests
from reliq import RQ
import requests

reliq = RQ(cached="True")


class RequestError(Exception):
    pass


class AuthorizationError(Exception):
    pass


def strtomd5(string: str | bytes) -> str:
    if isinstance(string, str):
        string = string.encode()

    return hashlib.md5(string).hexdigest()


def bool_get(obj: dict, name: str, otherwise: bool = False) -> bool:
    x = obj.get(name)
    if x is None:
        return otherwise
    return bool(x)


def int_get(obj: dict, name: str, otherwise: int = 0) -> int:
    x = obj.get(name)
    if x is None:
        return otherwise
    return int(x)


def float_get(obj: dict, name: str, otherwise: float = 0) -> float:
    x = obj.get(name)
    if x is None:
        return otherwise
    return float(x)


def dict_get(obj: dict, name: str) -> dict:
    x = obj.get(name)
    if not isinstance(x, dict):
        return {}
    return x


class hdporncomics:
    """
    kwarg( user_agent: str = "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0" ) - user agent

    kwarg( timeout: int = 30 ) - timeout

    kwarg( retries: int = 3 ) - number of retries in case of non fatal failure

    kwarg( retry_wait: float = 60 ) - waiting time before retrying

    kwarg( wait: float = 0 ) - waiting time in seconds in between requests

    kwarg( wait_random: int = 0 ) - random waiting time in milliseconds in between requests

    kwarg( logger: Optional[TextIO] = None ) - file to which requests log will be written, e.g. sys.stderr or sys.stdout

    fingerprint is generated at initialization so method( login ) is not needed unless you want to change it or log in.

    Its recommended to set kwarg( wait ).

    Any function requiring being logged in executed without it will raise hdporncomics.Authorization.

    Any request error will raise hdporncomics.RequestError.
    """

    def __init__(self, **kwargs):
        settings = {"visited": False}
        settings.update(kwargs)

        self.ses = treerequests.Session(
            requests,
            requests.Session,
            lambda x, y: treerequests.reliq(x, y, obj=reliq),
            requesterror=RequestError,
            **settings,
        )

        self.jwt = ""
        self.userinfo = {}
        self.fingerprint = self.get_fingerprint()

    @staticmethod
    def get_comic_fname(url: str) -> str:
        """
        Makes file name based on arg( url )

        returns( file name )
        """

        url = re.sub(r"/$", "", url)
        url = re.sub(
            r"-(free(-cartoon)?-porn-comic|sex-comic|gay-manga|manhwa-porn)$", "", url
        )
        url = re.sub(r".*/", "", url)
        return url

    @staticmethod
    def comic_link_from_id(c_id: int) -> str:
        """
        Creates url to comic from its id arg( c_id )

        returns ( url to comic )
        """
        return "https://hdporncomics.com/?p={}".format(str(c_id))

    @staticmethod
    def image_to_thumb(upload: str) -> str:
        """
        Converts url of image to its thumbnail version

        returns( url to thumbnail )
        """

        if upload.find("://pics.hdpo"):
            return upload

        if upload.find("://m.hdpo") != -1:
            return upload.replace("/images/", "/thumbs/", count=1)

        if upload.find("/images/") == -1:
            return upload.replace("/uploads/", "/thumbs/", count=1)

        return re.sub(r"(/\d+)(\.[a-zA-Z0-9]+)$", r"\1_t\2", upload)

    @staticmethod
    def image_to_upload(thumb: str) -> str:
        """
        Converts url of thumbnail to its upload version

        returns( url to upload )
        """

        # images with subdomain `pics.` all have the `_th` suffix and vice versa.
        # As seen below it's impossible to convert inbetween them so they should be ignored. They take only 0.652% of images.

        # https://hdporncomics.com/y3df-who-did-it-3-free-cartoon-porn-comic/

        # https://pics.hdporncomics.com/bigImages/y3df-Your3DFantasy_com-Comics/Who-Did-It/Issue-3/y3df-Your3DFantasy_com-Comics-Who-Did-It-Issue-3-003.jpg
        # https://pics.hdporncomics.com/thumbs/Your3DFantasy_com-Comics-Who-Did-It-Issue-3-003_th.jpg

        if thumb.find("://pics.hdpo"):
            return thumb

        if thumb.find("://m.hdpo") != -1:
            return thumb.replace("/thumbs/", "/images/", count=1)

        if thumb.find("/images/") == -1:
            return thumb.replace("/thumbs/", "/uploads/", count=1)

        return re.sub(r"(/\d+)_t(\.[a-zA-Z0-9]+)$", r"\1\2", thumb)

    def _get_view(self, c_id: int) -> dict:
        return self.ses.post_json(
            "https://hdporncomics.com/api/v1/posts/{}/view?postStats=true".format(c_id),
        )

    def view(self, c_id: int, add: bool = True) -> bool | dict:
        """
        Views comic or deletes it from history by arg( c_id ) depending on arg( add ).
        Comic can be deleted from history for logged in user.

        returns( True for success )
        """
        if add:
            r = self._get_view(c_id)
            if r["message"] != "Post added to history successfully":
                return False
            return True
        else:
            self._logged()

            r = self.ses.delete_json(
                "https://hdporncomics.com/api/v1/posts/{}/history".format(c_id)
            )
            if r["message"] != "Post removed from history successfully":
                return False
            return True

    def get_comic_likes(self, c_id: int, likes: bool = True) -> dict:
        ret = {
            "likes": -1,
            "dlikes": -1,
            "views": -1,
            "favorites": -1,
        }

        if not likes:
            return ret

        r = self._get_view(c_id)
        if isinstance(r, dict):
            ret["likes"] = r["post_likes"]
            ret["dlikes"] = r["post_dislikes"]
            ret["views"] = r["post_views"]
            ret["favorites"] = r["post_favorites"]

        return ret

    def get_comments_clean(self, c: list[dict]) -> list[dict]:
        ret = []
        for i in c:
            ret.append(
                {
                    "id": i["comment_ID"],
                    "user": i["comment_author"],
                    "userid": i["user_id"],
                    "avatar": i["profile_pic"],
                    "content": i["content"],
                    "likes": i["likes"],
                    "posted": self.conv_relative_date(i["posted_on"]),
                    "children": self.get_comments_clean(
                        [] if i.get("children") == None else i["children"]
                    ),
                }
            )

        return ret

    def get_comments_get(self, url: str, page: int) -> dict:
        r = self.ses.get_json(url)

        comments = self.get_comments_clean(r["data"])
        nexturl = r["links"]["next"]

        return {"comments": comments, "page": page, "nexturl": nexturl}

    def get_comments(self, c_id: int, page: int = 1, top: bool = False) -> Generator:
        """
        Gets comments for comic by its id arg( c_id ), starting from arg( page ) page.

        If arg( top ) is True they will be sorted by their score, otherwise sorted by date starting from the newest.

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comments.json )
        returns( Generator passing through pages of comments )
        """

        sorttype = "likes" if top else "newest"
        url = (
            "https://hdporncomics.com/api/v1/posts/{}/comments?page={}&sort={}".format(
                c_id, page, sorttype
            )
        )

        return self.go_through_pages(url, self.get_comments_get)

    def get_comic_comments_onpage_comment(self, rq: reliq) -> dict:
        children = []
        for i in rq.filter(r"ul L@[1] .children; li child@").self():
            children.append(self.get_comic_comments_onpage_comment(i))

        r = rq.json(
            r"""
            [0] * l@[1] #b>div-comment-; {
                .id.u @ | "%(id)v" / sed "s/.*-//",
                .avatar.U [0] img | "%(src)v",
                .user [0] cite | "%Di" trim,
                .posted [0] a c@[0] i@et>" ago" | "%i",
                .content * .comment-text; p child@ | "%Di\n\n" / trim sed "s/ *<br \/> */\n/g"
            }
            """
        )

        # these are not delivered
        r["likes"] = 0
        r["userid"] = 0

        r["children"] = children
        r["posted"] = self.conv_relative_date(r["posted"])

        return r

    def get_comic_comments_onpage(self, rq: reliq) -> list[dict]:
        comments = []
        for i in rq.filter(
            r"div #form_comments; [0] ol .commentlist; li child@"
        ).self():
            comments.append(self.get_comic_comments_onpage_comment(i))

        return comments

    def get_comic_comments(self, rq: reliq, c_id: int, comments: int) -> dict:
        r = {"comments": [], "comments_pages": 0}

        if comments == 0:
            r["comments"] = self.get_comic_comments_onpage(rq)
            return r

        r_comments = []
        comments_pages = 0

        for i in self.get_comments(c_id):
            r_comments += i["comments"]

            comments_pages += 1
            if comments != -1 and comments_pages >= comments:
                break

        r["comments"] = r_comments
        r["comments_pages"] = comments_pages

        return r

    def get_comic_dates(self, rq: reliq) -> dict:
        published = ""
        modified = ""
        for i in json.loads(rq.search('[0] script type=application/ld+json | "%i"'))[
            "@graph"
        ]:
            if i["@type"] == "WebPage":
                published = i["datePublished"]
                modified = i["dateModified"]
                break

        return {"published": published, "modified": modified}

    def get_comic(
        self, url: str, c_id: int = 0, comments: int = 0, likes: bool = True
    ) -> dict:
        """
        Gets comic based on arg( url ) or if arg( c_id ) is not 0 by the id.

        If arg( likes ) is set to True, it will make additional request to get fields "likes", "dlikes", "favorites", "views", otherwise they will be set to 0. This requests adds comic to history and increases it's view count.

        If arg( comments ) is set to 0 no additional requests for comments will be made and one page of comments will be scraped from html, although "likes" and "userid" fields will be set to 0 as they are not available.

        if arg( comments ) is set to -1 all comments will be scraped, other numbers will limit number of scraped comment pages.

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic.json )
        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic2.json )
        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic.json )
        returns( Dictionary of comic metadata )
        """

        if c_id != 0:
            url = self.comic_link_from_id(c_id)
        rq = self.ses.get_html(url)

        comic = rq.json(
            r"""
            .cover.U * #imgBox; [0] img | "%(src)v",
            div #infoBox; {
                .title h1 child@ | "%Di" trim / sed "s/ ((free )?(Cartoon )?Porn Comics?|Sex Comics?|Comic Porn|comic porn|(– ?)?Gay (Manga|Yaoi))$//" "E",
                .tags.a [0] span i@t>"Tags :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .artists.a [0] span i@t>"Artist :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .categories.a [0] span i@t>"Category :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .groups.a [0] span i@t>"Group :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .genres.a [0] span i@t>"Genre :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .sections.a [0] span i@t>"Section :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .languages.a [0] span i@t>"Language :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .characters.a [0] span i@t>"Characters :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .images_count.u span .postImages | "%i",
            },
            .published [0] meta property="article:published_time" content | "%(content)v",
            .modified [0] meta property="article:modified_time" content | "%(content)v",
            .id.u [0] link rel=shortlink href | "%(href)v" / sed "s#.*=##",
            .images.a.U div .my-gallery; figure child@; a itemprop=contentUrl child@ | "%(href)v\n",
            .related * #related-comics; article child@; {
                .name [0] h2 child@; [0] * c@[0] i@>[1:] | "%Di" trim sed "s/ *: *$//",
                .items * .slider-item; a [0]; {
                    [0] img; {
                        .cover.U @ | "%(src)v",
                        .title @ | "%(alt)Dv" trim / sed "s/^(Porn Comics|Gay Manga) - //; s/ – Gay Manga$//" "E",
                    },
                    .link.U @ | "%(href)v"
                } |
            } | ,
            .comments_count.u [0] * #comments-title | "%i" / sed "s/ .*//; s/^One$/1/"
            """
        )

        if len(comic["published"]) == 0 or len(comic["modified"]) == 0:
            comic.update(self.get_comic_dates(rq))

        comic["url"] = url
        c_id = comic["id"]

        comic.update(self.get_comic_likes(c_id, likes))

        comic.update(self.get_comic_comments(rq, c_id, comments))

        return comic

    def get_manhwa_chapter(self, url: str, comments: int = 0) -> dict:
        """
        Gets manhwa chapter based on arg( url ).

        arg( comments ) works the same way as for method( get_comic ).

        When using method( get_comments ) the id used should be ['manhwa']['id'] as the comment section for chapters is the same as for the manhwa.

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa-chapter.json )
        returns( Dictionary of manhwa chapter metadata )
        """

        rq = self.ses.get_html(url)

        r = rq.json(
            r"""
            .id.u [0] div #E>post-[0-9]+ | "%(id)v",
            .title div #selectChapter; [0] option selected | "%Di" trim,
            .manhwa {
                .id.u [0] article id="comicComments" data-post_id | "%(data-post_id)v",
                div #breadCrumb; [-] a; {
                    .link @ | "%(href)v",
                    .title @ | "%DT"
                }
            },
            .images.a.U div #imageContainer; img | "%(src)v\n",
            .comments_count.u [0] * #comments-title | "%i" / sed "s/ .*//; s/^One$/1/",
            """
        )
        r["url"] = url

        r.update(self.get_comic_dates(rq))

        r.update(self.get_comic_comments(rq, r["manhwa"]["id"], comments))

        return r

    def get_manhwa(
        self, url: str, c_id: int = 0, comments: int = 0, likes: bool = True
    ) -> dict:
        """
        Gets manhwa based on arg( url ) or if arg( c_id ) is not 0 by the id.

        arg( likes ) works the same way as for method( get_comic ).
        arg( comments ) works the same way as for method( get_comic ).

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa.json )
        returns( Dictionary of manhwa metadata )
        """

        if c_id != 0:
            url = self.comic_link_from_id(c_id)
        rq = self.ses.get_html(url)

        manhwa = rq.json(
            r"""
            .cover.U * #imgBox; [0] img | "%(src)v",
            div #infoBox; {
                .title h1 child@ | "%Di" trim / sed "s/ ( Manhwa Porn )$//",
                .artists.a [0] span i@t>"Artist :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .authors.a [0] span i@t>"Author :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .genres.a [0] span i@t>"Genre :"; [0] * ssub@; a c@[0] | "%i\n" / decode,
                .altname [0] span .alternateName | "%i",
                .status span .status | "%i"
            },
            .modified [0] meta property="article:modified_time" content | "%(content)v",
            .id.u [0] link rel=shortlink href | "%(href)v" / sed "s#.*=##",
            .comments_count.u [0] * #comments-title | "%i" / sed "s/ .*//; s/^One$/1/",
            .summary [0] div #summary | "%DT" trim "\n",
            .chapters div #eachChapter; {
                [0] a; {
                    .link.U @ | "%(href)v", -- they might have '//' inside them but they are the same as in the browser
                    .name @ | "%DT"
                },
                .date [0] span | "%T" trim "\n"
            } |
            """
        )

        manhwa["url"] = url

        r = self.get_comic_dates(rq)
        manhwa["published"] = r["published"]
        if len(manhwa["modified"]) == 0:
            manhwa["modified"] = r["modified"]

        c_id = manhwa["id"]

        manhwa.update(self.get_comic_likes(c_id, likes))

        manhwa.update(self.get_comic_comments(rq, c_id, comments))

        for i in manhwa["chapters"]:
            i["date"] = self.conv_chapter_datetime(i["date"])

        return manhwa

    def get_comic_file(
        self, url: str, c_id: int = 0, comments: int = 0, likes: bool = True
    ) -> Optional[str]:
        """
        Downloads comic into a file passing all arguments to method( get_comic ).

        returns( file name or None if file already exists )
        """

        fname = self.get_comic_fname(url)
        if os.path.exists(fname):
            return None

        comic = self.get_comic(url, c_id=c_id, comments=comments, likes=likes)

        with open(fname, "w") as f:
            f.write(json.dumps(comic))

        return fname

    @staticmethod
    def conv_relative_date(date: str) -> str:
        i = 0
        datel = len(date)
        while i < datel and date[i].isdigit():
            i += 1
        n = int(date[:i])

        while i < datel and date[i].isspace():
            i += 1

        if len(date) >= 4 and date[-4:] == " ago":
            date = date[:-4]

        if date[-1] == "s":
            date = date[:-1]

        mult: float = 0
        match date[i:]:
            case "second":
                mult = 1
            case "minute":
                mult = 60
            case "hour":
                mult = 3600
            case "day":
                mult = 3600 * 24
            case "week":
                mult = 3600 * 24 * 7
            case "month":
                mult = 3600 * 24 * 30.5
            case "year":
                mult = 3600 * 24 * 365.25
            case _:
                raise Exception("unknown date format")

        return datetime.fromtimestamp(
            (datetime.now().timestamp() - int(n * mult))
        ).isoformat()

    @staticmethod
    def conv_chapter_datetime(date: str) -> str:
        if len(date) == 0:
            return date

        return datetime.strptime(date, "%b %d, %y").isoformat()

    @staticmethod
    def get_pages_posts_views(views: str) -> int:
        viewsl = len(views)
        if viewsl == 0:
            return 0
        i = 0
        hasdot = 0
        while i < viewsl and (views[i].isdigit() or (views[i] == "." and not hasdot)):
            if views[i] == ".":
                hasdot = 1
            i += 1
        n = float(views[:i])

        if i < viewsl:
            c = views[i].lower()
            if c == "k":
                n *= 1000
            elif c == "m":
                n *= 1000000
            else:
                raise Exception("unknown views format")
            i += 1

        assert viewsl == i
        return int(n)

    def get_pages_posts(self, rq: reliq) -> list[dict]:
        posts = rq.json(
            r"""
            .posts div #all-posts; div #B>post-[0-9]* -has@"[0] ins .adsbyexoclick" child@; {
                .id.u @ | "%(id)v",
                div .comic-image child@; {
                    .cover.U [0] img | "%(src)v",
                    .date [0] span .text-base c@[0] | "%Di"
                },
                div .text-white child@; {
                    [0] a child@; {
                        .link.U @ | "%(href)v",
                        .title [0] * c@[0] i@>[1:] | "%Di" sed "s/ (comic porn|free Cartoon Porn Comic)$//" "E"
                    },
                    .views [0] span c@[0] i@et>" Views" | "%i" sed "s/ .*//",
                    .images.u [0] span c@[0] i@et>" Images" | "%i",
                    .likes.u svg .voteUp; [0] * spre@; span self@ | "%i",
                    .dlikes.u svg .voteDown; [0] * ssub@; span self@ | "%i",

                    span .scrollTaxonomy child@; {
                        .tags.a a rel=tag | "%i\n" / decode,
                        .chapters {
                            [0] * ssub@; div .flex self@; div .flex child@ ||
                            a -rel
                        }; {
                           [0] a; {
                                .link.U @ | "%(href)v",
                                .title [0] * c@[0] i@>[1:] | "%Di" trim
                            },
                           .date [0] span c@[0] child@ | "%i"
                        } |
                    }
                }
            } |
        """
        )["posts"]

        for i in posts:
            i["views"] = self.get_pages_posts_views(i["views"])
            i["date"] = self.conv_relative_date(i["date"])

            for j in i["chapters"]:
                j["date"] = self.conv_chapter_datetime(j["date"])

        return posts

    def get_page(self, url: str, page: int = 1) -> dict:
        rq = self.ses.get_html(url)

        nexturl = rq.json(r'.u.U [0] * .nav-links; [0] a .next | "%(href)Dv" trim')["u"]

        lastpage = rq.json(
            r'.l.u [0] * .nav-links; [-] a c@[0] .page-numbers i@Et>^[0-9,]+$ | "%i" tr ","'
        )["l"]

        term_id = rq.json(
            r'.l.u [0] * #subscribe-box | "%(data-taxid)v" / sed "/^$/s/^/0/"'
        )["l"]

        return {
            "url": url,
            "nexturl": nexturl,
            "page": page,
            "lastpage": lastpage,
            "term_id": term_id,
            "posts": self.get_pages_posts(rq),
        }

    def go_through_pages(self, url: str, func: Callable) -> Generator:
        nexturl = url
        page = 1
        while True:
            paged = func(nexturl, page)
            nexturl = paged["nexturl"]

            yield paged

            if nexturl is None or len(nexturl) == 0:
                break
            page += 1

    def get_pages(self, url: str) -> Generator:
        """
        Gets pages of comics, gay comics or manhwa by arg( url )

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic-page.json )
        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic-page.json )
        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa-page.json )
        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/artist-page.json )
        returns( Generator passing through pages of comics )
        """

        return self.go_through_pages(url, self.get_page)

    def get_new(self) -> Generator:
        """
        Gets comics starting from the newest from url( https://hdporncomics.com/ ).

        returns( initialized method( get_pages ) )
        """

        return self.get_pages("https://hdporncomics.com/")

    def get_gay(self) -> Generator:
        """
        Gets gay comics starting from the newest from url( https://hdporncomics.com/gay-manga/ ).

        returns( initialized method( get_pages ) )
        """

        return self.get_pages("https://hdporncomics.com/gay-manga/")

    def get_manhwas(self) -> Generator:
        """
        Gets manhwas starting from the newest from url( https://hdporncomics.com/manhwa/ ).

        returns( initialized method( get_pages ) )
        """

        return self.get_pages("https://hdporncomics.com/manhwa/")

    def get_comic_series(self) -> Generator:
        """
        Gets series of comics starting from the newest from url( https://hdporncomics.com/comic-series/ ).

        returns( initialized method( get_pages ) )
        """

        return self.get_pages("https://hdporncomics.com/comic-series/")

    @staticmethod
    def get_fingerprint():
        return strtomd5(str(random.randint(0, 10**20)))

    def login(self, email: str = "", password: str = "") -> bool:
        """
        Logs user in, if email or password is empty just changes the fingerprint.

        returns( False in case of failure )
        """
        self.logout()
        self.fingerprint = self.get_fingerprint()
        if len(email) == 0 or len(password) == "":
            return True

        try:
            s = self.ses.new()
            r = s.post_json(
                "https://hdporncomics.com/api/auth/login",
                data={"email": email, "password": password},
            )
        except RequestError:
            raise AuthorizationError()

        if r["message"] != "Authenticated":
            return False

        data = r["data"]
        jwt = data["jwt"]

        userinfo = json.loads(base64.b64decode(jwt.split(".")[1] + "=="))
        userinfo["expires_in"] = data["expires_in"]

        self.userinfo = userinfo
        self.jwt = jwt

        self.ses.headers.update({"Authorization": "Bearer " + jwt})
        self.ses.cookies.set("hd_JWT", jwt, domain="hdporncomics.com")
        return True

    def logout(self) -> bool:
        """
        Logs user out, is run automatically when using method( login ).

        returns( False in case of failure )
        """

        self.fingerprint = ""
        self.jwt = ""
        self.userinfo = {}

        suc = True
        try:
            self.ses.headers.pop("Authorization")
        except:
            suc = False
        try:
            self.ses.cookies.pop("hd_JWT")
        except:
            suc = False
        return suc

    def like(self, c_id: int, like: bool = True) -> bool:
        """
        Upvotes or downvotes comic by arg( c_id ) depending on arg( like ).
        Once voted you cannot unvote, only switch between upvote and downvote.

        returns( True for success )
        """

        ld = "voteUp" if like else "voteDown"

        r = self.ses.post_json(
            "https://hdporncomics.com/api/v1/posts/{}/like".format(c_id),
            data={"vote_type": ld, "user_fingerprint": self.fingerprint},
        )

        if r["message"] != "Success":
            return False
        return True

    def comment_like(self, co_id: int, like: bool = True) -> bool:
        """
        Likes or removes like from comment with id arg( co_id ) depending on arg( like ).
        User has to be logged in.

        returns( True for success )
        """

        self._logged()
        url = "https://hdporncomics.com/api/v1/comments/{}/like".format(co_id)

        if like:
            r = self.ses.post_json(url, data={})
            if r["message"] != "Comment liked successfully":
                return False
        else:
            r = self.ses.delete_json(url, data={})
            if r["message"] != "Comment like removed successfully":
                return False

        return True

    def comment_delete(self, co_id: int) -> bool:
        """
        Deletes comment by its id arg( co_id ).
        User has to be logged in.

        returns( True for success )
        """
        self._logged()
        r = self.ses.delete_json(
            "https://hdporncomics.com/api/v1/user/comments/{}".format(co_id)
        )
        if r["message"] != "Success":
            return False
        return True

    def _logged(self):
        if len(self.jwt) == 0:
            raise AuthorizationError()

    def favorite(self, c_id: int, add: bool = True) -> bool:
        """
        Adds comic by arg( c_id ) to favorites or removes depending on arg( add ).
        Comic can be removed only for logged in user.

        returns( True for success )
        """

        url = "https://hdporncomics.com/api/v1/posts/{}/favorite".format(c_id)
        if add:
            r = self.ses.post_json(url, data={})
            if r["message"] != "Post added to favorites successfully":
                return False
            return True
        else:
            self._logged()  # you have to be logged to unfavorite but not to favorite
            r = self.ses.delete_json(url, data={})
            if r["message"] != "Post removed from favorites successfully":
                return False
            return True

    def report(self, c_id: int):
        # There is no reporting implemented on the site, any attempts to do so send no requests
        pass

    def comment(self, c_id: int, text: str, parent: int = 0) -> bool:
        """
        Posts a comment on comic with id arg( c_id ) and contents of arg( text ).

        if arg( parent ) is set to id of other comment the posted comment will be a response.

        returns( True for success )
        """

        r = self.ses.post_json(
            "https://hdporncomics.com/api/v1/posts/{}/comments".format(c_id),
            data={"comment_body": text, "comment_parrent": parent},
        )  # unfortunetely it doesn't return id of created comment
        if r["message"] == "Success":
            return True
        return False

    def comment_edit(self, co_id: int, text: str) -> bool:
        """
        Theoretically edits comment with id arg( co_it ) to arg( text ).
        Unfortunately this puts the comic into verification mode, and until some admin approves of the change it will become visible.
        It's better to treat it as another method( comment_delete ) that draws attention to mods :)

        returns( True for success )
        """

        self._logged()

        r = self.ses.put_json(
            "https://hdporncomics.com/api/v1/user/comments/{}".format(co_id),
            data={"new_comment_content": text},
        )
        if r["message"] != "Success":
            return False
        return True

    def get_stats(self) -> dict:
        """
        Gets stats of the site found on url( https://hdporncomics.com/stats/ ).

        returns( Dictionary of site stats )
        """

        rq = self.ses.get_html("https://hdporncomics.com/stats/")

        return rq.json(
            r"""
            [0] div .post-content; {
                .comics.u dt i@ft>"Porn Comics"; [0] * ssub@; dd self@ | "%i",
                .gay.u dt i@ft>"Gay Manga"; [0] * ssub@; dd self@ | "%i",
                .manhwa.u dt i@ft>"Manhwa"; [0] * ssub@; dd self@ | "%i",

                .artists.u dt i@ft>"Artists"; [0] * ssub@; dd self@ | "%i",
                .categories.u dt i@ft>"Categories"; [0] * ssub@; dd self@ | "%i",
                .characters.u dt i@ft>"Characters"; [0] * ssub@; dd self@ | "%i",
                .groups.u dt i@ft>"Groups"; [0] * ssub@; dd self@ | "%i",
                .parodies.u dt i@ft>"Parodies"; [0] * ssub@; dd self@ | "%i",
                .tags.u dt i@ft>"Tags"; [0] * ssub@; dd self@ | "%i",

                .comments.u dt i@ft>"Comments"; [0] * ssub@; dd self@ | "%i",
                .users.u dt i@ft>"Users"; [0] * ssub@; dd self@ | "%i",
                .moderators.u dt i@ft>"Moderators"; [0] * ssub@; dd self@ | "%i",

                .most_active_users [0] h3 i@ft>"User With Most Comments"; [0] * ssub@; div .relative; {
                    .avatar [0] img | "%(src)v",
                    [0] a; {
                        .link @ | "%(href)v",
                        .user p | "%Di" trim
                    }
                } |
            }
            """
        )

    def get_gay_or_manhwa_list(self, url: str) -> dict:
        rq = self.ses.get_html(url)

        return rq.json(
            r"""
            .id.u [0] * #E>post-[0-9]+ | "%(id)v",
            .list * #mcTagMap; ul .links; li -.morelink child@; {
                [0] a; {
                    .link @ | "%(href)v",
                    .name [0] * c@[0] | "%Di" trim
                },
                .count.u span .mctagmap_count | "%i"
            } |
            """
        )

    def get_manhwa_artists_list(self) -> dict:
        """
        Gets a list of manhwa artists from url( https://hdporncomics.com/manhwa-artists/ )

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa-artists-list.json )
        returns( List of manhwa artists )
        """

        return self.get_gay_or_manhwa_list("https://hdporncomics.com/manhwa-artists/")

    def get_manhwa_authors_list(self) -> dict:
        """
        Gets a list of manhwa authors from url( https://hdporncomics.com/manhwa-authors/ )

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa-authors-list.json )
        returns( List of manhwa authors )
        """

        return self.get_gay_or_manhwa_list("https://hdporncomics.com/manhwa-authors/")

    def get_manhwa_genres_list(self) -> dict:
        """
        Gets a list of manhwa genres from url( https://hdporncomics.com/manhwa-genres/ )

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa-genres-list.json )
        returns( List of manhwa genres )
        """

        return self.get_gay_or_manhwa_list("https://hdporncomics.com/manhwa-genres/")

    def get_gay_genres_list(self) -> dict:
        """
        Gets a list of gay comic genres from url( https://hdporncomics.com/gay-manga-genres/ )

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic-genres-list.json )
        returns( List of gay comic genres )
        """

        return self.get_gay_or_manhwa_list("https://hdporncomics.com/gay-manga-genres/")

    def get_gay_groups_list(self) -> dict:
        """
        Gets a list of gay comic groups from url( https://hdporncomics.com/gay-manga-groups/ )

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic-groups-list.json )
        returns( List of gay comic groups )
        """

        return self.get_gay_or_manhwa_list("https://hdporncomics.com/gay-manga-groups/")

    def get_gay_languages_list(self) -> dict:
        """
        Gets a list of gay comic languages from url( https://hdporncomics.com/gay-manga-languages/ )

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic-languages-list.json )
        returns( List of gay comic languages )
        """

        return self.get_gay_or_manhwa_list(
            "https://hdporncomics.com/gay-manga-languages/"
        )

    def get_gay_sections_list(self) -> dict:
        """
        Gets a list of gay comic sections from url( https://hdporncomics.com/gay-manga-section/ )

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic-sections-list.json )
        returns( List of gay comic sections )
        """

        return self.get_gay_or_manhwa_list(
            "https://hdporncomics.com/gay-manga-section/"
        )

    def get_list_page_posts(self, rq: reliq) -> list[dict]:
        return rq.json(
            r"""
            .posts [0] section id; div .categoryCard child@; {
                [0] a; {
                    .cover.U [0] img | "%(src)v",
                    .link.U @ | "%(href)v"
                },
                [0] h3; text@ [0] *; {
                    .name @ / sed "s/ ( [0-9]* )$//" decode trim,
                    .count.u @ / sed "s/.*(//; s/).*//; s/ //g"
                }
            } |
            """
        )["posts"]

    def get_list_page(self, url: str, page: int = 1) -> dict:
        rq = self.ses.get_html(url)

        nexturl = rq.json(r'.u.U [0] * #navigation; [0] a .next | "%(href)Dv" trim')[
            "u"
        ]

        lastpage = rq.json(
            r'.l.u [0] * #navigation; [-] a c@[0] .page-numbers i@Et>^[0-9]+$ | "%i"'
        )["l"]

        ret = {
            "url": url,
            "nexturl": nexturl,
            "page": page,
            "lastpage": lastpage,
            "posts": self.get_list_page_posts(rq),
        }

        return ret

    def get_comics_list_url(self, url: str) -> Generator:
        """
        Gets list of comic terms from arg( url ).

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic-artists-list.json )
        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic-groups-list.json )
        returns( Generator passing through pages of comic terms )
        """

        return self.go_through_pages(url, self.get_list_page)

    def get_comics_list(
        self, ctype: str, page: int = 1, sort: str = "", search: str = ""
    ) -> Generator:
        """
        Initiates method( get_comics_list_url ).

        arg( ctype ) indicates the type of term, it can take value of "parodies", "artists", "groups", "categories", "tags", "characters".

        arg( sort ) sets sorting algorithm it can take value of "likes", "views", "favorites", "count".

        arg( page ) specifies starting page.

        arg( search ) filters the titles of terms.

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic-artists-list.json )
        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic-groups-list.json )
        returns( Generator passing through pages of comic terms )
        """

        possible_sort = ["likes", "views", "favorites", "count"]
        possible_ctype = [
            "parodies",
            "artists",
            "groups",
            "categories",
            "tags",
            "characters",
        ]

        if ctype not in possible_ctype:
            raise Exception("Bad ctype arg (look at help())")
        if len(sort) != 0 and sort not in possible_sort:
            raise Exception("Bad sort arg (look at help())")

        pageinurl = ""
        if page > 1:
            pageinurl = "page/{}/".format(page)

        sortinurl = ""
        if len(sort) > 0:
            sortinurl = "&orderby={}".format(sort)

        searchinurl = "&alphabet={}".format(search) if len(search) > 0 else ""

        url = "https://hdporncomics.com/comics/{}/{}?page&pagename=comics%2F{}{}{}".format(
            ctype, pageinurl, ctype, sortinurl, searchinurl
        )

        return self.get_comics_list_url(url)

    def get_terms(self, ctype: str) -> list:
        """
        Gets a list of all terms based on arg( ctype ).

        arg( ctype ) can take values of "artist", "parody", "tags", "groups", "characters", "category".

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/terms-artist.json )
        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/terms-characters.json )
        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/terms-tags.json )
        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/terms-comments.json )
        returns( List of terms )
        """

        possible_ctype = [
            "artist",
            "parody",
            "tags",
            "groups",
            "characters",
            "category",
        ]

        if ctype not in possible_ctype:
            raise Exception("Bad ctype arg (look at help())")

        r = self.ses.get_json(
            "https://hdporncomics.com/api/v1/taxonomy/{}/terms".format(ctype)
        )

        ret = []

        r = json.loads(r["jsonData"])

        if ctype == "parody":
            t = []
            for i in r:
                t.append(r[i])
            r = t

        for i in r:
            i.pop("tax")
            ret.append(i)

        return ret

    def subscribe(self, term_id: int, add: bool = True) -> bool:
        """
        Subscribes or unsubscribes to arg( term_id ) depending on arg( add ). Works only for logged in user.

        Id of terms can be found by either method( get_terms ) or method( get_pages ) on specific term page.

        returns( True for success )
        """

        self._logged()

        url = "https://hdporncomics.com/api/v1/term/{}/subscribe".format(term_id)
        if add:
            r = self.ses.post_json(url, data={})
            if r != "Success":
                return False
            return True
        else:
            r = self.ses.delete_json(url, data={})
            if r != "Success":
                return False
            return True

    def get_dashboard_stats(self) -> dict:
        """
        Gets dashboard stats of logged in user.

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/dashboard-stats.json )
        returns( Dictionary of dashboard stats )
        """

        self._logged()

        r = self.ses.get_json("https://hdporncomics.com/api/v1/dashboard/")

        return {
            "likes": r["total_likes"],
            "favorites": r["total_favorites"],
            "history": r["total_history"],
            "comments": r["total_comments"],
        }

    def get_history_page(self, url: str, page: int = 1) -> dict:
        r = self.ses.get_json(url)

        posts = []
        for i in r["data"]:
            attr = i["attributes"]
            stats = attr["stats"]
            posts.append(
                {
                    "type": i["type"],
                    "id": i["id"],
                    "title": re.sub(
                        r" (free Cartoon Porn Comic|Comic Porn|comic porn|– Gay Manga)$",
                        "",
                        attr["title"],
                    ),
                    "link": attr["url"],
                    "cover": attr["thumbnail"],
                    "views": stats["viewCount"],
                    "likes": stats["upVoteCount"],
                    "dlikes": stats["downVoteCount"],
                    "favorites": stats["favoriteCount"],
                    "comments": stats["commentCount"],
                    "created": attr["created_at"],
                    "modified": attr["updated_at"],
                }
            )

        return {
            "url": url,
            "nexturl": r["links"]["next"],
            "page": page,
            "lastpage": r["meta"]["last_page"],
            "posts": posts,
        }

    def get_history(self) -> Generator:
        """
        Gets a list of viewed comics of logged in user.

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/history.json )
        returns( Generator passing through pages of viewed comics )
        """

        self._logged()
        return self.go_through_pages(
            "https://hdporncomics.com/api/v1/user/history?page=1",
            self.get_history_page,
        )

    def get_liked(self) -> Generator:
        """
        Gets a list of liked comics of logged in user.

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/liked.json )
        returns( Generator passing through pages of liked comics )
        """

        self._logged()
        return self.go_through_pages(
            "https://hdporncomics.com/api/v1/user/likes?page=1",
            self.get_history_page,
        )

    def get_favorites(self) -> Generator:
        """
        Gets a list of favored comics of logged in user.

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/favorites.json )
        returns( Generator passing through pages of favored comics )
        """

        self._logged()
        return self.go_through_pages(
            "https://hdporncomics.com/api/v1/user/favorites?page=1",
            self.get_history_page,
        )

    def get_subscriptions(self) -> list[dict]:
        """
        Gets a list of subscribed terms made by logged in user.

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/subscriptions.json )
        returns( List of subscribed terms )
        """

        self._logged()
        r = self.ses.get_json(
            "https://hdporncomics.com/api/v1/user/subscriptions?page=1"
        )

        terms = []
        for i in r["subscribed_terms"]:
            terms.append(
                {
                    "id": i["term_id"],
                    "name": i["name"],
                    "count": i["count"],
                    "link": i["url"],
                }
            )

        return terms

    def get_user_comments_page(self, url: str, page: int = 1) -> dict:
        r = self.ses.get_json(url)

        posts = []
        for i in r["data"]:
            posts.append(
                {
                    "id": i["comment_ID"],
                    "comic_id": i["comment_post_ID"],
                    "comic_link": i["post_url"],
                    "user": i["comment_author"],
                    "userid": i["user_id"],
                    "content": i["content"],
                    "parent": i["comment_parrent"],
                    "date": self.conv_relative_date(i["posted_on"]),
                    "likes": i["likes"],
                    "replies": i["replies"],
                    "avatar": i["profile_pic"],
                }
            )

        return {
            "url": url,
            "nexturl": r["links"]["next"],
            "page": page,
            "lastpage": r["meta"]["last_page"],
            "posts": posts,
        }

    def get_user_comments(self) -> Generator:
        """
        Gets a list of comments made by logged in user.

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/user-comments.json )
        returns( Generator passing through pages of comments )
        """

        self._logged()
        return self.go_through_pages(
            "https://hdporncomics.com/api/v1/user/comments/?page=1",
            self.get_user_comments_page,
        )

    def get_notifications_page(self, url: str, page: int = 1) -> dict:
        r = self.ses.get_json(url)

        nexturl = None
        if r["has_more"]:
            nexturl = re.sub(r"=\d+$", "=" + str(r["current_page"] + 1), url)

        notifications = []
        for i in r["notifications"]:
            notifications.append(
                {
                    "title": i["comic_title"],
                    "link": i["comic_link"],
                    "type": i["notification_type"],
                    "date": i["notification_time"],
                    "id": i["notification_id"],
                }
            )

        return {
            "url": url,
            "nexturl": nexturl,
            "page": page,
            "lastpage": r["total"],
            "notifications": notifications,
        }

    def get_notifications(self) -> Generator:
        """
        Gets notifications for logged in user

        It doesn't remove them, for that use method( notifications_clean )

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/notifications.json )

        returns( Generator passing through notification pages )
        """

        self._logged()
        return self.go_through_pages(
            "https://hdporncomics.com/api/v1/user/notifications?page=1",
            self.get_notifications_page,
        )

    def notifications_clean(self) -> bool:
        """
        Cleans all notifications for logged in user

        returns( True for success )
        """

        r = self.ses.delete_json("https://hdporncomics.com/api/v1/user/notifications")
        if r["message"] != "All notifications deleted successfully":
            return False
        return True

    def get_user(self, url: str) -> dict:
        """
        Gets basic info about user from arg( url )

        exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/user.json )
        returns( Dictionary of user metadata )
        """

        rq = self.ses.get_html(url)

        ret = rq.json(
            r"""
            .id.u [0] link rel=alternate href=Ee>"/v2/users/[0-9]+" | "%(href)v" / sed "s#.*/##",
            .name div #userName; [-] span | "%Dt" trim,
            .joined dt i@t>Joined; [0] * ssub@; dd self@ | "%i",
            .lastseen dt i@t>"Last Seen"; [0] * ssub@; dd self@ | "%i",
            .comments.u dt i@t>Comments; [0] * ssub@; dd self@ | "%i"
            """
        )
        ret["lastseen"] = self.conv_relative_date(ret["lastseen"])
        ret["joined"] = self.conv_relative_date(ret["joined"])
        ret["url"] = url
        return ret

    def search(self, search: str) -> Generator:
        """
        Searches for arg( search ) in titles of comics

        returns( initialized method( get_pages ) )
        """

        url = (
            "https://hdporncomics.com/?s={}&s_extra[]=title&s_extra[]=taxonomy".format(
                search
            )
        )
        return self.get_pages(url)

    def guess(self, url: str) -> Optional[Callable]:
        """
        Guesses scraping method based on the arg( url )

        returns( the found method or None if nothing matched )
        """

        r = re.match(r"^(https?://hdporncomics.com)(\?.*|/.*|$)", url)
        if r is None:
            return None

        url = r[2]

        def pagep(x):
            return (
                x
                + r"(/page/\d+)?(/(\?sort=(view|random|date|likes|favorites|images|comments|hotness))?)?"
            )

        matches = [
            (r"/stats/", self.get_stats),
            (r"/author/[^/]+/?", self.get_user),
            (pagep("/trending"), None),
            (pagep(r"/(comic-series|gay-manga|manhwa)"), self.get_pages),
            (pagep(r"/comic-series/[^/]+"), self.get_pages),
            (pagep(r"/(artist|tag|category|p-group|pcharacter)/[^/]+"), self.get_pages),
            (pagep(r"/(genre|section|group|language)/[^/]+"), self.get_pages),
            (pagep(r"/manhwa-(artist|author|genre)/[^/]+"), self.get_pages),
            (
                r"/?p=\d+",
                self.get_comic,
            ),
            (
                r"/gay-manga/[^/]+(/(#.*)?)?",
                self.get_comic,
            ),
            (
                r"/manhwa/[^/]+(/(#.*)?)?",
                self.get_manhwa,
            ),
            (
                r"/[^/]+(-free)?(((-cartoon)?-porn|-sex)-comic(s*|-2)|-comic-porn|-gay-manga)(/(#.*)?)?",
                self.get_comic,
            ),
            (
                r"/manhwa/[^/]+//?[^/]+(/(#.*)?)?",
                self.get_manhwa_chapter,
            ),
            (
                r"/manhwa-(artists|authors|genres)(/(#.*)?)?",
                self.get_gay_or_manhwa_list,
            ),
            (
                r"/gay-manga-(genres|groups|languages|section)(/(#.*)?)?",
                self.get_gay_or_manhwa_list,
            ),
            (
                r"/comics/(artists|groups|parodies|categories|tags|characters)(/page/\d+)?(/(\?.*)?)?",
                self.get_comics_list_url,
            ),
            (
                pagep(
                    r"(/page/\d+/)?\?s=[^&]*&s_extra\[[^\]]*\]=title&s_extra\[[^\]]*\]=taxonomy"
                ),
                self.get_pages,
            ),
            (pagep(r""), self.get_pages),
            (r"/[^/]+(/(#.*)?)?", self.get_comic),
        ]

        for i in matches:
            if re.fullmatch(i[0], url):
                return i[1]

        return None
