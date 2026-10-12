"""
SQL injection detection. Does passive error pattern first, then active time based.

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

Limitation: DVWA only responds properly if you're logged in and have the
security level cookie. For now you have to log into DVWA yourself, copy the
cookie header from the browser devtools and paste it into the "cookie" field
on the scan form. Doing the DVWA login automatically is a TODO.
"""
import statistics
import time

import requests

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


def run_passive_detection(url, param_names, cookie_header=None, timeout=6):
    """
    Returns a list of dicts like this:
      {parameter_name, detection_method, payload_used, finding_classification}
    There's one dict for each parameter. It stops at the first payload that
    triggers an error so that one is what gets saved.
    """
    headers = {"Cookie": cookie_header} if cookie_header else {}
    results = []

    for param in param_names:
        classification = "CLEAN"
        triggering_payload = None

        for payload in PROBE_PAYLOADS:
            try:
                resp = requests.get(
                    url,
                    params={param: payload},
                    headers=headers,
                    timeout=timeout,
                )
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


def _elapsed_ms(url, param, payload, headers, timeout):
    """Sends one request and returns (elapsed_ms, timed_out, error).

    If it times out I count that as delayed, not as a failure, because a
    SLEEP() payload that works can make the request go past the timeout.
    Any other error (like the host being down) gets returned as `error`.
    """
    start = time.monotonic()
    try:
        requests.get(url, params={param: payload}, headers=headers, timeout=timeout)
    except requests.Timeout:
        return (timeout * 1000.0, True, None)
    except requests.RequestException as exc:
        return (None, False, exc)
    return ((time.monotonic() - start) * 1000.0, False, None)


def calibrate_baseline(url, param, cookie_header=None, samples=5, timeout=10):
    """Measures how long the target normally takes to respond.

    Sends a few normal requests (just the value "1", no injection) and returns
    {mean_response_ms, stddev_response_ms, sample_count}. Returns None if all
    of them failed (target is down). This is the "adaptive" part, the threshold
    comes from timing this target instead of using a hardcoded number.
    """
    headers = {"Cookie": cookie_header} if cookie_header else {}
    timings = []
    for _ in range(samples):
        elapsed, _timed_out, error = _elapsed_ms(url, param, "1", headers, timeout)
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


def run_active_time_based_detection(url, param_names, baseline, cookie_header=None):
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
    threshold_ms = (
        baseline["mean_response_ms"]
        + BASELINE_STDDEV_MULTIPLIER * baseline["stddev_response_ms"]
        + DELAY_MARGIN_MS
    )
    results = []

    for param in param_names:
        classification = "CLEAN"
        triggering_payload = None

        for template in TIME_PAYLOAD_TEMPLATES:
            payload = template.format(d=DELAY_SECONDS)

            # try once first, only do the repeats if this one is slow (saves time)
            elapsed, _timed_out, error = _elapsed_ms(
                url, param, payload, headers, ACTIVE_TIMEOUT)
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
                    url, param, payload, headers, ACTIVE_TIMEOUT)
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
