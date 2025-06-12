# hdporncomics

An unofficial api for [hdporncomics](https://hdporncomics.com/).

# Installation

    pip install hdporncomics

# Output examples

Are created by `create-format-examples` script and contained in [examples](https://github.com/TUVIMEN/hdporncomics/tree/master/examples) directory. Files are in `json` format.

# Usage

## CLI

THIS THING DOWNLOADS IMAGES!!!!!!!!!!!

[demonstration video](https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/cli-usage-demonstration.mkv)

CLI interface uses very little of implemented functions and is used only for downloading comics/manhwas/chapters and pages of them.

Download resource from URLs into DIR

    hdporncomics --directory DIR URL1 URL2 URL3

This will create separate directory named by title of resource where images and data will be stored e.g. for `https://hdporncomics.com/myaxx-human-experiments-planz34-sex-comic/` it will create

```
Myaxx Human Experiments
Myaxx Human Experiments/1.jpg
Myaxx Human Experiments/2.jpg
Myaxx Human Experiments/3.jpg
Myaxx Human Experiments/4.jpg
Myaxx Human Experiments/5.jpg
Myaxx Human Experiments/6.jpg
Myaxx Human Experiments/7.jpg
Myaxx Human Experiments/8.jpg
Myaxx Human Experiments/info.json
```

where `info.json` stores the basic information. By default comments are not scraped if you want to get all comments for all resources use `--comment-limit -1` option.

Getting manhwas will create chapters directories under the directory of manhwa.

Pages of things don't create directories for themselves but they still create `info.json` although in different format.

By default images are named by their order and stylized with zeroes - this is much more practical approach as it won't mess up order of them by sorting files. If you want to have the original names use the `--no-num-images` option.

Download only images without metadata using 8 threads (only images are downloaded using multiple threads)

    hdporncomics --directory DIR --threads 8 --images-only URL1 URL2 URL3

Download comics with all comments and wait 1.2 seconds in between requests and randomly up to 800 milliseconds (waiting time doesn't affect downloading images)

    hdporncomics --directory DIR --wait 1.2 --wait-random 800 URL1 URL2

Download resources from URLs annotating their type

    hdporncomics --directory DIR --chapter URL1 --chapter URL2 --pages URL3 --comic URL4 --manhwa URL5 URL6 URL7

### General

`--help` - print help message

`--version` - print version

`--threads NUM`  - amount of threads used to download images

### Files

`--directory DIR` - enter directory before downloading

`--force` - overwrite things

`--no-num-images` - use original names of saved images

### Types

`--chapter URL` - treat the following url as manhwa chapter

`--manhwa URL` - treat the following url as manhwa

`--comic URL` - treat the following url as comic

`--pages URL` - treat the following url as pages

### Settings

`--images-only` - download only images, don't save any metadata

`--noimages` - save only metadata

`--nochapters` - don't download chapters when downloading manhwas

`--comment-limit NUM` - limit of number of comment pages traversed, `-1` disables this limit, by default set to `0`

`--pages-max NUM` - limit of pages traversed when getting pages

### Request settings

`--wait FLOAT` - waiting time in seconds

`--wait-random MILISECONDS` - random waiting time up to `MILISECONDS`

`--retries NUM` - number of retries for failed requests

`--retry-wait FLOAT` - waiting time in seconds between retries

`--timeout SECONDS` - connection timeout

`--insecure` - disable ssl checks

`--location` - follow redirections

`--user-agent UA` - set custom user agent

`--proxies` - set requests proxies dictionary, e.g. -x \'{"http":"127.0.0.1:8080","ftp":"0.0.0.0"}\'

`--header` - set header, can be used multiple times e.g. -H 'User: Admin' -H 'Pass: 12345'

`--cookies` - set cookie, can be used multiple times e.g. -b 'auth=8f82ab' -b 'PHPSESSID=qw3r8an829'

## Library

### Code

```python
import os
import re
from datetime import datetime, timedelta
from hdporncomics import hdporncomics, RequestError, AuthorizationError

hdpo = hdporncomics(wait=1.2)

# login is not required, you can still comment, like, favorite without it
try:
    hdpo.login(os.environ("HDPORNCOMICS_EMAIL", "HDPORNCOMICS_PASSWORD"))
except AuthorizationError:
    raise Exception("could not log in")

# if you aren't logging in, but want to change fingerprint use
hdpo.login()

# go through 3 first pages of the newest comics and comment "cheese" for each comic
page = 1
for i in hdpo.get_new():
    for j in i["posts"]:
        assert hdpo.comment(j["id"], "cheese") is True

        for g in hdpo.get_comments(j["id"]):
            for k in g["comments"]:
                if (
                    k["content"].find("apple") != -1
                ):  # like comments that have 'apple' in them
                    hdpo.comment_like(k["id"])
                elif (
                    k["content"].find("pear") != -1
                ):  # dislike comment that have 'pear' in them
                    hdpo.comment_like(k["id"], False)
                elif (
                    k["content"].find("DELETE") != -1
                ):  # reply to comments that have 'DELETE' in them
                    hdpo.comment(j["id"], "no", parent=k["comment"])

        # add comic to favorites
        c = hdpo.get_comic(k["id"])
        if c["comments_count"] > 10 and (
            len(c["artists"]) > 0 or len(c["categories"]) > 0
        ):
            hdpo.favorite(k["id"])
        elif "Foot Fetish" in c["tags"]:  # downvote comic
            hdpo.like(k["id"], False)

    if page >= 3:
        break
    page += 1

# subscribe to every artist that has numbers at the end of it's name
for i in hdpo.get_terms("artist"):
    if re.match(r"[0-9]+$", i["name"]):
        assert hdpo.favorite(i["id"]) is True

# unsubscribe all characters that don't have space in their name
for i in hdpo.get_terms("characters"):
    if re.match(r"^[^ ]+$"):
        assert hdpo.favorite(i["id", False]) is True

hdpo.get_subscriptions()  # returns subscribed terms

# remove comics from history that have not been modified since last year
lastyear = datetime.now() - timedelta(seconds=365 * 24 * 60 * 60)
for i in hdpo.get_history():
    for j in i["posts"]:
        if j["modified"] < lastyear:
            hdpo.view(j["id"], False)

# search for "red"
try:
    for i in hdpo.search("red"):
        for j in i["posts"]:
            print(i["views"])
except RequestError:
    print("request failed")

# return function processing the url
url = "https://hdporncomics.com/comics/artists/?page&pagename=comics/artists&orderby=views"
func = hdpo.guess(url)
if func is not None:
    print(func(url))
```

### Methods

#### hdporncomics

kwarg( user_agent: str = "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0" ) - user agent

kwarg( proxies: dict ) - requests lib proxies

kwarg( headers: dict ) - requests lib headers

kwarg( cookies: dict ) - requests lib cookies

kwarg( timeout: int = 30 ) - timeout

kwarg( verify: bool = True ) - use ssl

kwarg( allow_redirects: bool = False ) - allow for redirections

kwarg( retries: int = 3 ) - number of retries in case of non fatal failure

kwarg( retry_wait: float = 60 ) - waiting time before retrying

kwarg( wait: float = 0 ) - waiting time in seconds in between requests

kwarg( wait_random: int = 0 ) - random waiting time in milliseconds in between requests

kwarg( logger: Optional[TextIO] = None ) - file to which requests log will be written, e.g. sys.stderr or sys.stdout

fingerprint is generated at initialization so method( login ) is not needed unless you want to change it or log in.

Its recommended to set kwarg( wait ).

Any function requiring being logged in executed without it will raise hdporncomics.Authorization.

Any request error will raise hdporncomics.RequestError.

#### get_comic_fname(url: str) -> str

Makes file name based on arg( url )

returns( file name )

#### comic_link_from_id(c_id: int) -> str

Creates url to comic from its id arg( c_id )

returns ( url to comic )

#### image_to_thumb(upload: str) -> str

Converts url of image to its thumbnail version

returns( url to thumbnail )

#### image_to_upload(thumb: str) -> str

Converts url of thumbnail to its upload version

returns( url to upload )

#### view(self, c_id: int, add: bool = True) -> bool | dict

Views comic or deletes it from history by arg( c_id ) depending on arg( add ).

Comic can be deleted from history for logged in user.

returns( True for success )

#### get_comments(self, c_id: int, page: int = 1, top: bool = False) -> Generator

Gets comments for comic by its id arg( c_id ), starting from arg( page ) page.

If arg( top ) is True they will be sorted by their score, otherwise sorted by date starting from the newest.

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comments.json )

returns( Generator passing through pages of comments )

#### get_comic(self, url: str, c_id: int = 0, comments: int = 0, likes: bool = True) -> dict

Gets comic based on arg( url ) or if arg( c_id ) is not 0 by the id.

If arg( likes ) is set to True, it will make additional request to get fields "likes", "dlikes", "favorites", "views", otherwise they will be set to 0. This requests adds comic to history and increases it's view count.

If arg( comments ) is set to 0 no additional requests for comments will be made and one page of comments will be scraped from html, although "likes" and "userid" fields will be set to 0 as they are not available.

if arg( comments ) is set to -1 all comments will be scraped, other numbers will limit number of scraped comment pages.

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic.json )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic2.json )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic.json )

returns( Dictionary of comic metadata )

#### get_manhwa_chapter(self, url: str, comments: int = 0) -> dict

Gets manhwa chapter based on arg( url ).

arg( comments ) works the same way as for method( get_comic ).

When using method( get_comments ) the id used should be ['manhwa']['id'] as the comment section for chapters is the same as for the manhwa.

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa-chapter.json )

returns( Dictionary of manhwa chapter metadata )

#### get_manhwa(self, url: str, c_id: int = 0, comments: int = 0, likes: bool = True) -> dict

Gets manhwa based on arg( url ) or if arg( c_id ) is not 0 by the id.

arg( likes ) works the same way as for method( get_comic ).

arg( comments ) works the same way as for method( get_comic ).

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa.json )

returns( Dictionary of manhwa metadata )

#### get_comic_file(self, url: str, c_id: int = 0, comments: int = 0, likes: bool = True) -> Optional[str]

Downloads comic into a file passing all arguments to method( get_comic ).

returns( file name or None if file already exists )

#### get_pages(self, url: str) -> Generator

Gets pages of comics, gay comics or manhwa by arg( url )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic-page.json )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic-page.json )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa-page.json )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/artist-page.json )

returns( Generator passing through pages of comics )

#### get_new(self) -> Generator

Gets comics starting from the newest from url( https://hdporncomics.com/ ).

returns( initialized method( get_pages ) )

#### get_gay(self) -> Generator

Gets gay comics starting from the newest from url( https://hdporncomics.com/gay-manga/ ).

returns( initialized method( get_pages ) )

#### get_manhwas(self) -> Generator

Gets manhwas starting from the newest from url( https://hdporncomics.com/manhwa/ ).

returns( initialized method( get_pages ) )

#### get_comic_series(self) -> Generator

Gets series of comics starting from the newest from url( https://hdporncomics.com/comic-series/ ).

returns( initialized method( get_pages ) )

#### login(self, email: str = "", password: str = "") -> bool

Logs user in, if email or password is empty just changes the fingerprint.

returns( False in case of failure )

#### logout(self) -> bool

Logs user out, is run automatically when using method( login ).

returns( False in case of failure )

#### like(self, c_id: int, like: bool = True) -> bool

Upvotes or downvotes comic by arg( c_id ) depending on arg( like ).

Once voted you cannot unvote, only switch between upvote and downvote.

returns( True for success )

#### comment_like(self, co_id: int, like: bool = True) -> bool

Likes or removes like from comment with id arg( co_id ) depending on arg( like ).

User has to be logged in.

returns( True for success )

#### comment_delete(self, co_id: int) -> bool

Deletes comment by its id arg( co_id ).
User has to be logged in.

returns( True for success )

#### favorite(self, c_id: int, add: bool = True) -> bool

Adds comic by arg( c_id ) to favorites or removes depending on arg( add ).
Comic can be removed only for logged in user.

returns( True for success )

#### comment(self, c_id: int, text: str, parent: int = 0) -> bool

Posts a comment on comic with id arg( c_id ) and contents of arg( text ).

if arg( parent ) is set to id of other comment the posted comment will be a response.

returns( True for success )

#### comment_edit(self, co_id: int, text: str) -> bool

Theoretically edits comment with id arg( co_it ) to arg( text ).
Unfortunately this puts the comic into verification mode, and until some admin approves of the change it will become visible.
It's better to treat it as another method( comment_delete ) that draws attention to mods :)

returns( True for success )

#### get_stats(self) -> dict

Gets stats of the site found on url( https://hdporncomics.com/stats/ ).

returns( Dictionary of site stats )

#### get_manhwa_artists_list(self) -> dict

Gets a list of manhwa artists from url( https://hdporncomics.com/manhwa-artists/ )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa-artists-list.json )

returns( List of manhwa artists )

#### get_manhwa_authors_list(self) -> dict

Gets a list of manhwa authors from url( https://hdporncomics.com/manhwa-authors/ )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa-authors-list.json )

returns( List of manhwa authors )

#### get_manhwa_genres_list(self) -> dict

Gets a list of manhwa genres from url( https://hdporncomics.com/manhwa-genres/ )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/manhwa-genres-list.json )

returns( List of manhwa genres )

#### get_gay_genres_list(self) -> dict

Gets a list of gay comic genres from url( https://hdporncomics.com/gay-manga-genres/ )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic-genres-list.json )

returns( List of gay comic genres )

#### get_gay_groups_list(self) -> dict

Gets a list of gay comic groups from url( https://hdporncomics.com/gay-manga-groups/ )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic-groups-list.json )

returns( List of gay comic groups )

#### get_gay_languages_list(self) -> dict

Gets a list of gay comic languages from url( https://hdporncomics.com/gay-manga-languages/ )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic-languages-list.json )

returns( List of gay comic languages )

#### get_gay_sections_list(self) -> dict

Gets a list of gay comic sections from url( https://hdporncomics.com/gay-manga-section/ )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/gay-comic-sections-list.json )

returns( List of gay comic sections )

#### get_comics_list_url(self, url: str) -> Generator

Gets list of comic terms from arg( url ).

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic-artists-list.json )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic-groups-list.json )

returns( Generator passing through pages of comic terms )

return self.go_through_pages(url, self.get_list_page)

#### get_comics_list(self, ctype: str, page: int = 1, sort: str = "", search: str = "") -> Generator

Initiates method( get_comics_list_url ).

arg( ctype ) indicates the type of term, it can take value of "parodies", "artists", "groups", "categories", "tags", "characters".

arg( sort ) sets sorting algorithm it can take value of "likes", "views", "favorites", "count".

arg( page ) specifies starting page.

arg( search ) filters the titles of terms.

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic-artists-list.json )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/comic-groups-list.json )

returns( Generator passing through pages of comic terms )

#### get_terms(self, ctype: str) -> list

Gets a list of all terms based on arg( ctype ).

arg( ctype ) can take values of "artist", "parody", "tags", "groups", "characters", "category".

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/terms-artist.json )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/terms-characters.json )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/terms-tags.json )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/terms-comments.json )

returns( List of terms )

#### subscribe(self, term_id: int, add: bool = True) -> bool

Subscribes or unsubscribes to arg( term_id ) depending on arg( add ). Works only for logged in user.

Id of terms can be found by either method( get_terms ) or method( get_pages ) on specific term page.

returns( True for success )

#### get_dashboard_stats(self) -> dict

Gets dashboard stats of logged in user.

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/dashboard-stats.json )

returns( Dictionary of dashboard stats )

#### get_history(self) -> Generator

Gets a list of viewed comics of logged in user.

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/history.json )

returns( Generator passing through pages of viewed comics )

#### get_liked(self) -> Generator

Gets a list of liked comics of logged in user.

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/liked.json )

returns( Generator passing through pages of liked comics )

#### get_favorites(self) -> Generator

Gets a list of favored comics of logged in user.

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/favorites.json )

returns( Generator passing through pages of favored comics )

#### get_subscriptions(self) -> list[dict]

Gets a list of subscribed terms made by logged in user.

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/subscriptions.json )

returns( List of subscribed terms )

#### get_user_comments(self) -> Generator

Gets a list of comments made by logged in user.

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/user-comments.json )

returns( Generator passing through pages of comments )

#### get_notifications(self) -> Generator

Gets notifications for logged in user

It doesn't remove them, for that use method( notifications_clean )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/notifications.json )


returns( Generator passing through notification pages )

#### notifications_clean(self) -> bool

Cleans all notifications for logged in user

returns( True for success )

#### get_user(self, url: str) -> dict

Gets basic info about user from arg( url )

exampleout( https://raw.githubusercontent.com/TUVIMEN/hdporncomics/refs/heads/master/examples/user.json )

returns( Dictionary of user metadata )

#### search(self, search: str) -> Generator

Searches for arg( search ) in titles of comics

returns( initialized method( get_pages ) )

#### guess(self, url: str) -> Optional[Callable]

Guesses scraping method based on the arg( url )

returns( the found method or None if nothing matched )

## Scraping whole site

At the root of this project is a python tool named `hdporncomics-scrape`. It utilizes this library to scrape the whole site. It does so in a sophisticated way, going through all list pages until saved links don't start overlapping or until the views of already found resources are greater by the factor of 1.3 from the saved ones.

All gathered links are saved into `links` file. All resources are saved into their respective directory that can be `manhwachapter`, `comic`, `gay` or `manhwa`. All files under these are named by sha256 of their url.

All comments of resources are downloaded, exception to this are manhwa chapters since their comment section is the same as their parent manhwa.

After downloading all of these resources and their comment sections there is nothing on site that cannot be generated from these, so scraping things like artists, tags, genres is counter productive, if you need them generate them.

If this tool is run after some time it will update file structure with new resources and resources that got a lot of activity since.

This tool takes only one argument which is the working directory

    ./hdporncomics-scrape DIR

By default the waiting time is 1 second before each request, at this speed it takes about a week to finish everything. You may go faster, to change the waiting time go to the end of `hdporncomics-scrape` file and change the waiting argument of `hdporncomics` class.

As per 2025-03-28 file structure generated consists of:

| path         | size | file count   |
| ----         | ---- | ----------   |
| ./w          | 1.6G | 203645       |
| ./w/links    | 16M  | 203639 lines |
| ./w/comic    | 773M | 74323        |
| ./w/gay      | 476M | 38960        |
| ./w/manhwa   | 17M  | 1629         |
| ./w/chapters | 308M | 88727        |

Above that the count of images is 7579740

    find comic gay manhwachapter -type f | xargs -x -n 50 jq -r '.images | length' | awk '{ c += $0 } END { print c }'

and the count of comments is 587164

    find comic gay manhwa -type f | xargs -x -n 50 jq 'def tchild: . | map((.children | tchild) + 1) | add; .comments | tchild'  | awk '{ c += $0 } END { print c }'

If your script got interrupted in the middle of scraping, there is a chance that chapter links were not saved to `links` file, you can correct that by running

    { find manhwa -type f | xargs jq -r '.chapters[].link'; cat links; } | sort -u | sponge links

## Results

You can see scraped results [here](https://huggingface.co/datasets/hexderm/hdporncomics).
