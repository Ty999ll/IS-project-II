"""
Remembers the user's logged-in session on each target site, so they log in to
the target once and can then run several scans (and sandbox re-tests) against
it without re-entering credentials or pasting a cookie each time.

Saved per target origin (scheme://host:port) in the Flask session, which is
tied to this app's own login and cleared when the user logs out.

Limitations: only the target's session cookie is kept, never the password, so
once the target expires that session (DVWA after ~24 min idle or a restart) the
user has to enter the login details again; the form is pre-filled with the
login URL and username to make that quick. Flask's session cookie is signed,
not encrypted, so the saved target cookie is readable in this user's own
browser - acceptable for a test-target session, but not for real credentials.
"""
from datetime import datetime
from urllib.parse import urlparse

from flask import session

_KEY = "target_sessions"


def origin_of(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}".lower()


def get_saved(url):
    """The saved session for this URL's site, or None."""
    return session.get(_KEY, {}).get(origin_of(url))


def save(url, cookie_header, login_url="", login_user=""):
    saved = dict(session.get(_KEY, {}))
    saved[origin_of(url)] = {
        "cookie": cookie_header,
        "login_url": login_url,
        "login_user": login_user,
        "saved_at": datetime.now().strftime("%H:%M"),
    }
    session[_KEY] = saved


def forget(url):
    saved = dict(session.get(_KEY, {}))
    saved.pop(origin_of(url), None)
    session[_KEY] = saved


def all_saved():
    return session.get(_KEY, {})
