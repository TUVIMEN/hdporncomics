#!/usr/bin/env python
# by Dominik Stanisław Suchora <suchora.dominik7@gmail.com>
# License: GNU GPLv3

import time
import random
import hashlib
import os
import re
import json
import base64
from datetime import datetime

from reliq import reliq

import requests
from urllib.parse import urljoin


class RequestError(Exception):
    pass


class AuthorizationError(Exception):
    pass


def strtomd5(string):
    if isinstance(string, str):
        string = string.encode()

    return hashlib.md5(string).hexdigest()


def int_get(obj, name, otherwise=0):
    x = obj.get(name)
    if x is None:
        return otherwise
    return int(x)


def float_get(obj, name, otherwise=0):
    x = obj.get(name)
    if x is None:
        return otherwise
    return float(x)


class Session(requests.Session):
    def __init__(self, **kwargs):
        super().__init__()

        self.timeout = int_get(kwargs, "timeout", 30)

        t = kwargs.get("user_agent")
        self.user_agent = (
            t
            if t is not None
            else "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0"
        )

        self.headers.update(
            {"User-Agent": self.user_agent, "Referer": "https://hdporncomics.com/"}
        )

        self.retries = int_get(kwargs, "retries", 3)
        self.retry_wait = float_get(kwargs, "retry_wait", 60)
        self.wait = float_get(kwargs, "wait")
        self.wait_random = int_get(kwargs, "wait_random")

        self.logger = kwargs.get("logger")

    @staticmethod
    def base(rq, url):
        ref = url
        u = rq.search(r'[0] head; [0] base href=>[1:] | "%(href)v"')
        if u != "":
            u = urljoin(url, u)
            if u != "":
                ref = u
        return ref

    def r_req_try(self, url, method, retry=False, **kwargs):
        if not retry:
            if self.wait != 0:
                time.sleep(self.wait)
            if self.wait_random != 0:
                time.sleep(random.randint(0, self.wait_random + 1) / 1000)

        if self.logger is not None:
            print(url, file=self.logger)

        if method == "get":
            return self.get(url, timeout=self.timeout, **kwargs)
        elif method == "post":
            return self.post(url, timeout=self.timeout, **kwargs)
        elif method == "delete":
            return self.delete(url, timeout=self.timeout, **kwargs)
        elif method == "put":
            return self.put(url, timeout=self.timeout, **kwargs)

    def r_req(self, url, method="get", **kwargs):
        tries = self.retries
        retry_wait = self.retry_wait

        instant_end_code = [400, 401, 402, 403, 404, 410, 412, 414, 421, 505]

        i = 0
        while True:
            try:
                resp = self.r_req_try(url, method, retry=(i != 0), **kwargs)
            except (
                requests.ConnectTimeout,
                requests.ConnectionError,
                requests.ReadTimeout,
                requests.exceptions.ChunkedEncodingError,
                RequestError,
            ):
                resp = None

            if resp is None or not (
                resp.status_code >= 200 and resp.status_code <= 299
            ):
                if resp is not None and resp.status_code in instant_end_code:
                    raise RequestError(
                        "failed completely {} {}".format(resp.status_code, url)
                    )
                if i >= tries:
                    raise RequestError(
                        "failed {} {}".format(
                            "connection" if resp is None else resp.status_code, url
                        )
                    )
                i += 1
                if retry_wait != 0:
                    time.sleep(retry_wait)
            else:
                return resp

    def get_html(self, url, return_cookies=False, **kwargs):
        resp = self.r_req(url, **kwargs)

        rq = reliq(resp.text)
        ref = self.base(rq, url)

        if return_cookies:
            return (rq, ref, resp.cookies.get_dict())
        return (rq, ref)

    def get_json(self, url, **kwargs):
        resp = self.r_req(url, **kwargs)
        return resp.json()

    def post_json(self, url, **kwargs):
        resp = self.r_req(url, method="post", **kwargs)
        return resp.json()

    def delete_json(self, url, **kwargs):
        resp = self.r_req(url, method="delete", **kwargs)
        return resp.json()

    def put_json(self, url, **kwargs):
        resp = self.r_req(url, method="put", **kwargs)
        return resp.json()


class hdporncomics:
    def __init__(self, **kwargs):
        self.ses = Session(
            **kwargs,
        )

        self.jwt = ""
        self.userinfo = {}
        self.fingerprint = self.get_fingerprint()

    @staticmethod
    def get_comic_fname(url):
        url = re.sub(r"/$", "", url)
        url = re.sub(
            r"-(free-cartoon-porn-comic|sex-comic|gay-manga|manhwa-porn)$", "", url
        )
        url = re.sub(r".*/", "", url)
        return url

    @staticmethod
    def comic_link_from_id(c_id):
        return "https://hdporncomics.com/?p={}".format(str(c_id))

    @staticmethod
    def comic_thumb(upload):
        return upload.replace("/uploads/", "/thumbs/", count=1)

    def view(self, c_id, add=True, _ret=False):
        if _ret:
            add = True
        if add:
            r = self.ses.post_json(
                "https://hdporncomics.com/api/v1/posts/{}/view?postStats=true".format(
                    c_id
                ),
            )
            if _ret:
                return r
            else:
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

    def get_comic_likes(self, c_id, likes=True):
        ret = {
            "likes": -1,
            "dlikes": -1,
            "views": -1,
            "favorites": -1,
        }

        if not likes:
            return ret

        r = self.view(c_id, _ret=True)

        ret["likes"] = r["post_likes"]
        ret["dlikes"] = r["post_dislikes"]
        ret["views"] = r["post_views"]
        ret["favorites"] = r["post_favorites"]

        return ret

    def get_comments_clean(self, c):
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

    def get_comments_get(self, url, page):
        r = self.ses.get_json(url)

        comments = self.get_comments_clean(r["data"])
        nexturl = r["links"]["next"]

        return {"comments": comments, "page": page, "nexturl": nexturl}

    def get_comments(self, c_id, page=1, top=False):
        sorttype = "likes" if top else "newest"
        url = (
            "https://hdporncomics.com/api/v1/posts/{}/comments?page={}&sort={}".format(
                c_id, page, sorttype
            )
        )

        return self.go_through_pages(url, self.get_comments_get)

    def get_comic_comments(self, c_id, comments):
        r = {"comments": [], "comments_pages": 0}

        if comments == 0:
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

    def get_comic_dates(self, rq):
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

    def get_comic(self, url, c_id=0, comments=0, likes=True):
        if c_id != 0:
            url = self.comic_link_from_id(c_id)
        rq, ref = self.ses.get_html(url)

        comic = json.loads(
            rq.search(
                r"""
            .cover * #imgBox; [0] img | "%(src)v",
            div #infoBox; {
                .title h1 child@ | "%Di" trim / sed "s/ (free Cartoon Porn Comic|Comic Porn|comic porn|– Gay Manga)$//" "E",
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
            .images.a div .my-gallery; img | "%(src)v\n",
            .related * #related-comics; article child@; {
                .name [0] h2 child@; [0] * c@[0] i@>[1:] | "%Di" trim sed "s/ *: *$//",
                .items * .slider-item; a [0]; {
                    [0] img; {
                        .cover @ | "%(src)v",
                        .title @ | "%(alt)Dv" trim / sed "s/^(Porn Comics|Gay Manga) - //; s/ – Gay Manga$//" "E",
                    },
                    .link @ | "%(href)v"
                } |
            } | ,
            .comments_count.u [0] * #comments-title | "%i" / sed "s/ .*//; s/^One$/1/"
        """
            )
        )

        if len(comic["published"]) == 0 or len(comic["modified"]) == 0:
            comic.update(self.get_comic_dates(rq))

        comic["url"] = url
        c_id = comic["id"]

        comic.update(self.get_comic_likes(c_id, likes))

        comic.update(self.get_comic_comments(c_id, comments))

        comic["cover"] = urljoin(ref, comic["cover"])
        for i, j in enumerate(comic["images"]):
            comic["images"][i] = urljoin(ref, j)

        for i in comic["related"]:
            for j in i["items"]:
                j["cover"] = urljoin(ref, j["cover"])
                j["link"] = urljoin(ref, j["link"])

        return comic

    def get_manhwa_chapter(self, url, comments=0):
        rq, ref = self.ses.get_html(url)

        r = json.loads(
            rq.search(
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
            .images.a div #imageContainer; img | "%(src)v\n",
            .comments_count.u [0] * #comments-title | "%i" / sed "s/ .*//; s/^One$/1/",
        """
            )
        )
        r["url"] = url

        r.update(self.get_comic_dates(rq))

        r.update(self.get_comic_comments(r["manhwa"]["id"], comments))

        return r

    def get_manhwa(self, url, c_id=0, comments=0, likes=True):
        if c_id != 0:
            url = self.comic_link_from_id(c_id)
        rq, ref = self.ses.get_html(url)

        manhwa = json.loads(
            rq.search(
                r"""
            .cover * #imgBox; [0] img | "%(src)v",
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
                    .link @ | "%(href)v",
                    .name @ | "%DT"
                },
                .date [0] span | "%T" trim "\n"
            } |
        """
            )
        )

        manhwa["url"] = url

        r = self.get_comic_dates(rq)
        manhwa["published"] = r["published"]
        if len(manhwa["modified"]) == 0:
            manhwa["modified"] = r["modified"]

        c_id = manhwa["id"]

        manhwa.update(self.get_comic_likes(c_id, likes))

        manhwa.update(self.get_comic_comments(c_id, comments))

        manhwa["cover"] = urljoin(ref, manhwa["cover"])

        for i in manhwa["chapters"]:
            i["link"] = urljoin(
                ref, i["link"]
            )  # they might have '//' inside them but they are the same as in the browser
            i["date"] = self.conv_chapter_datetime(i["date"])

        return manhwa

    def get_comic_file(self, url, c_id=0, commentpages=0, likes=True):
        fname = self.get_comic_fname(url)
        if os.path.exists(fname):
            return None

        comic = self.get_comic(url, c_id=c_id, commentpages=commentpages, likes=likes)

        with open(fname, "w") as f:
            f.write(json.dumps(comic))

        return fname

    @staticmethod
    def conv_relative_date(date):
        datetime.now()
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

        mult = 0
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
    def conv_chapter_datetime(date):
        if len(date) == 0:
            return date

        return datetime.strptime(date, "%b %d, %y").isoformat()

    @staticmethod
    def get_pages_posts_views(views):
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
            c = views[i]
            if c == "k":
                n *= 1000
            elif c == "m":
                n *= 1000000
            else:
                raise Exception("unknown views format")
            i += 1

        assert viewsl == i
        return int(n)

    def get_pages_posts(self, rq, ref):
        posts = json.loads(
            rq.search(
                r"""
            .posts div #all-posts; div #B>post-[0-9]* -has@"[0] ins .adsbyexoclick" child@; {
                .id.u @ | "%(id)v",
                div .comic-image child@; {
                    .cover [0] img | "%(src)v",
                    .date [0] span .text-base c@[0] | "%Di"
                },
                div .text-white child@; {
                    [0] a child@; {
                        .link @ | "%(href)v",
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
                                .link @ | "%(href)v",
                                .title [0] * c@[0] i@>[1:] | "%Di" trim
                            },
                           .date [0] span c@[0] child@ | "%i"
                        } |
                    }
                }
            } |
        """
            )
        )["posts"]
        for i in posts:
            i["views"] = self.get_pages_posts_views(i["views"])
            i["date"] = self.conv_relative_date(i["date"])
            i["cover"] = urljoin(ref, i["cover"])
            i["link"] = urljoin(ref, i["link"])

            for j in i["chapters"]:
                j["link"] = urljoin(ref, j["link"])
                j["date"] = self.conv_chapter_datetime(j["date"])

        return posts

    def get_page(self, url, page=1):
        rq, ref = self.ses.get_html(url)

        nexturl = rq.search(r'[0] * .nav-links; [0] a .next | "%(href)Dv" trim')
        if len(nexturl) != 0:
            nexturl = urljoin(ref, nexturl)

        lastpage = rq.search(
            r'[0] * .nav-links; [-] a c@[0] .page-numbers i@Et>^[0-9,]+$ | "%i" tr ","'
        )
        lastpage = 0 if len(lastpage) == 0 else int(lastpage)

        term_id = rq.search(
            r'[0] * #subscribe-box | "%(data-taxid)v" / sed "/^$/s/^/0/"'
        )
        term_id = 0 if len(term_id) == 0 else int(term_id)

        return {
            "url": url,
            "nexturl": nexturl,
            "page": page,
            "lastpage": lastpage,
            "term_id": term_id,
            "posts": self.get_pages_posts(rq, ref),
        }

    def go_through_pages(self, url, func):
        nexturl = url
        page = 1
        pages = []
        while True:
            paged = func(nexturl, page)
            nexturl = paged["nexturl"]

            yield paged

            if nexturl is None or len(nexturl) == 0:
                break
            page += 1

        return pages

    def get_pages(self, url):
        return self.go_through_pages(url, self.get_page)

    def get_new(self):
        return self.get_pages("https://hdporncomics.com/")

    def get_gay(self):
        return self.get_pages("https://hdporncomics.com/gay-manga/")

    def get_manhwas(self):
        return self.get_pages("https://hdporncomics.com/manhwa/")

    def get_comic_series(self):
        return self.get_pages("https://hdporncomics.com/comic-series/")

    @staticmethod
    def get_fingerprint():
        return strtomd5(str(random.randint(0, 10**20)))

    def login(self, email="", password=""):
        self.logout()
        self.fingerprint = self.get_fingerprint()
        if len(email) == 0 or len(password) == "":
            return True

        try:
            s = Session()
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

    def logout(self):
        self.fingerprint = ""
        self.jwt = ""
        self.userinfo = {}

        try:
            self.ses.headers.pop("Authorization")
        except:
            pass
        try:
            self.ses.cookies.pop("hd_JWT")
        except:
            pass

    def like(self, c_id, like=True):
        ld = "voteUp" if like else "voteDown"

        r = self.ses.post_json(
            "https://hdporncomics.com/api/v1/posts/{}/like".format(c_id),
            data={"vote_type": ld, "user_fingerprint": self.fingerprint},
        )

        if r["message"] == "Success":
            return True

    def comment_like(self, co_id, like=True):
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

    def comment_delete(self, co_id):
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

    def favorite(self, c_id, add=True):
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

    def report(self, c_id):
        # There is no reporting implemented on the site, any attempts to do so send no requests
        pass

    def comment(self, c_id, text, parent=0):
        r = self.ses.post_json(
            "https://hdporncomics.com/api/v1/posts/{}/comments".format(c_id),
            data={"comment_body": text, "comment_parrent": parent},
        )  # unfortunetely it doesn't return id of created comment
        if r["message"] == "Success":
            return True
        return False

    def comment_edit(self, co_id, text):
        self._logged()

        r = self.ses.put_json(
            "https://hdporncomics.com/api/v1/user/comments/{}".format(co_id),
            data={"new_comment_content": text},
        )
        if r["message"] != "Success":
            return False
        return True

    def get_stats(self):
        rq, ref = self.ses.get_html("https://hdporncomics.com/stats/")

        return json.loads(
            rq.search(
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
        )

    def get_gay_or_manhwa_list(self, url):
        rq, ref = self.ses.get_html(url)

        return json.loads(
            rq.search(
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
        )

    def get_manhwa_artists_list(self):
        return self.get_gay_or_manhwa_list("https://hdporncomics.com/manhwa-artists/")

    def get_manhwa_authors_list(self):
        return self.get_gay_or_manhwa_list("https://hdporncomics.com/manhwa-authors/")

    def get_manhwa_genres_list(self):
        return self.get_gay_or_manhwa_list("https://hdporncomics.com/manhwa-genres/")

    def get_gay_genres_list(self):
        return self.get_gay_or_manhwa_list("https://hdporncomics.com/gay-manga-genres/")

    def get_gay_groups_list(self):
        return self.get_gay_or_manhwa_list("https://hdporncomics.com/gay-manga-groups/")

    def get_gay_languages_list(self):
        return self.get_gay_or_manhwa_list(
            "https://hdporncomics.com/gay-manga-languages/"
        )

    def get_gay_sections_list(self):
        return self.get_gay_or_manhwa_list(
            "https://hdporncomics.com/gay-manga-section/"
        )

    def get_list_page_posts(self, rq, ref):
        r = json.loads(
            rq.search(
                r"""
            .posts [0] section id; div .categoryCard child@; {
                [0] a; {
                    .cover [0] img | "%(src)v",
                    .link @ | "%(href)v"
                },
                [0] h3; text@ [0] *; {
                    .name @ / sed "s/ ( [0-9]* )$//" decode trim,
                    .count.u @ / sed "s/.*(//; s/).*//; s/ //g"
                }
            } |
        """
            )
        )["posts"]

        for i in r:
            i["link"] = urljoin(ref, i["link"])
            i["cover"] = urljoin(ref, i["cover"])

        return r

    def get_list_page(self, url, page=1):
        rq, ref = self.ses.get_html(url)

        nexturl = rq.search(r'[0] * #navigation; [0] a .next | "%(href)Dv" trim')
        if len(nexturl) != 0:
            nexturl = urljoin(ref, nexturl)

        lastpage = rq.search(
            r'[0] * #navigation; [-] a c@[0] .page-numbers i@Et>^[0-9]+$ | "%i"'
        )
        if len(lastpage) == 0:
            lastpage = 0
        else:
            lastpage = int(lastpage)

        page = {
            "url": url,
            "nexturl": nexturl,
            "page": page,
            "lastpage": lastpage,
            "posts": self.get_list_page_posts(rq, ref),
        }

        return page

    def get_comics_list_url(self, url):
        return self.go_through_pages(url, self.get_list_page)

    def get_comics_list(self, ctype, page=1, sort="", search=""):
        """
        for some reason covers are generated depending on the url, and stay the same for them

        sort = "likes" "views" "favorites" "count"
        ctype = "parodies" "artists" "groups" "categories" "tags" "characters"
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

        searchinurl = ""
        if len(search) > 0:
            searchinurl = "&alphabet={}".format(searchinurl)

        url = (
            "https://hdporncomics.com/comics/{}/{}?page&pagename=comics/{}{}{}".format(
                ctype, pageinurl, ctype, sortinurl, searchinurl
            )
        )

        return self.get_comics_list_url(url)

    def get_terms(self, ctype):
        """
        ctype = "artist" "parody" "tags" "groups" "characters" "category"
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

    def subscribe(self, term_id, add=True):
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

    def get_dashboard_stats(self):
        self._logged()

        r = self.ses.get_json("https://hdporncomics.com/api/v1/dashboard/")

        return {
            "likes": r["total_likes"],
            "favorites": r["total_favorites"],
            "history": r["total_history"],
            "comments": r["total_comments"],
        }

    def get_history_page(self, url, page=1):
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

    def get_history(self):
        self._logged()
        return self.go_through_pages(
            "https://hdporncomics.com/api/v1/user/history?page=1",
            self.get_history_page,
        )

    def get_liked(self):
        self._logged()
        return self.go_through_pages(
            "https://hdporncomics.com/api/v1/user/likes?page=1",
            self.get_history_page,
        )

    def get_favorites(self):
        self._logged()
        return self.go_through_pages(
            "https://hdporncomics.com/api/v1/user/favorites?page=1",
            self.get_history_page,
        )

    def get_subscriptions(self):
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

    def get_user_comments_page(self, url, page=1):
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

    def get_user_comments(self):
        self._logged()
        return self.go_through_pages(
            "https://hdporncomics.com/api/v1/user/comments/?page=1",
            self.get_user_comments_page,
        )

    def get_notifications_page(self, url, page=1):
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

    def get_notifications(self):
        self._logged()
        return self.go_through_pages(
            "https://hdporncomics.com/api/v1/user/notifications?page=1",
            self.get_notifications_page,
        )

    def notifications_clean(self):
        r = self.ses.delete_json("https://hdporncomics.com/api/v1/user/notifications")
        if r["message"] != "All notifications deleted successfully":
            return False
        return True

    def get_user(self, url):
        rq, ref = self.ses.get_html(url)

        ret = json.loads(
            rq.search(
                r"""
            .id.u [0] link rel=alternate href=Ee>"/v2/users/[0-9]+" | "%(href)v" / sed "s#.*/##",
            .name div #userName; [-] span | "%Dt" trim,
            .joined dt i@t>Joined; [0] * ssub@; dd self@ | "%i",
            .lastseen dt i@t>"Last Seen"; [0] * ssub@; dd self@ | "%i",
            .comments.u dt i@t>Comments; [0] * ssub@; dd self@ | "%i"
        """
            )
        )
        ret["lastseen"] = self.conv_relative_date(ret["lastseen"])
        ret["joined"] = self.conv_relative_date(ret["joined"])
        ret["url"] = url
        return ret

    def search(self, search):
        url = (
            "https://hdporncomics.com/?s={}&s_extra[]=title&s_extra[]=taxonomy".format(
                search
            )
        )
        return self.get_pages(url)

    def guess(self, url):
        r = re.match(r"^(https?://hdporncomics.com)(/.*|$)", url)
        if r is None:
            return None

        url = r[2]

        def pagep(x):
            return (
                x
                + r"(/page/\d+)?(/(\?sort=(view|random|date|likes|favorites|images|comments|hotness))?)?"
            )

        matches = [
            (
                r"/?p=\d+",
                self.get_comic,
            ),
            (
                r"/(free-cartoon-porn-comic|sex-comic|gay-manga)/[^/]+/?",
                self.get_comic,
            ),
            (
                r"/manhwa-porn/[^/]+/?",
                self.get_manhwa,
            ),
            (
                r"/manhwa-porn/[^/]+/[^/]+/?",
                self.get_manhwa,
            ),
            (r"/stats/", self.get_stats),
            (r"/author/[^/]+/?", self.get_user),
            (pagep(r"/(comic-series|gay-manga|manhwa)"), self.get_pages),
            (pagep(r"/(artist|tag|category|p-group|pcharacter)/[^/]+"), self.get_pages),
            (pagep(r"/(genre|section|group|language)/[^/]+"), self.get_pages),
            (pagep(r"/manhwa-(artist|author|genre)/[^/]+"), self.get_pages),
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
        ]

        for i in matches:
            if re.fullmatch(i[0], url):
                return i[1]

        return None
