"""
SQL-injection detection: passive error-pattern, then active time-based.

Two of the three techniques in the proposal are implemented here:

  1. run_passive_detection()     — error-pattern matching (the simplest).
  2. run_active_time_based_detection() — timing-based, escalated to only when
     passive finds nothing, using an adaptive baseline (see calibrate_baseline).

Boolean-based blind is still NOT implemented; it's the next slice.

Active time-based detection works the way the Activity Diagram describes:
first measure the target's normal response time (calibrate_baseline), then
inject a delay payload and check whether the response is slower than the
baseline by a clear margin. To avoid false positives from network jitter, the
delay must show up CONSISTENTLY across repeated requests; a delay that appears
on some repeats but not all is reported as POSSIBLY_VULNERABLE rather than
confirmed.

Limitation to be upfront about: DVWA needs an authenticated session +
a security-level cookie to actually respond to requests. Pass that in as a raw
cookie header (copied from your browser's devtools after logging into DVWA
manually) via the "cookie" field on the scan form, rather than automating
DVWA's own login. Automating that is a reasonable "next slice" task.
"""
import statistics
import time

import requests

# --- Active time-based tuning ---------------------------------------------
DELAY_SECONDS = 5          # how long a vulnerable query is told to sleep
ACTIVE_REPEATS = 3         # timed requests used to confirm a delay is consistent
# A response counts as "delayed" if it exceeds the baseline mean by more than
# this many standard deviations PLUS a fixed margin (ms). The margin sits below
# DELAY_SECONDS so a real ~5s sleep clears it comfortably, while ordinary jitter
# (a few hundred ms over the mean) does not.
BASELINE_STDDEV_MULTIPLIER = 3
DELAY_MARGIN_MS = 4000
# Must exceed DELAY_SECONDS so a successful sleep returns rather than timing out.
ACTIVE_TIMEOUT = DELAY_SECONDS + 15

# Delay payloads. {d} is filled with DELAY_SECONDS. MySQL/MariaDB (DVWA) use
# SLEEP(); the WAITFOR variant covers SQL Server targets.
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
    "' OR SLEEP(0)-- -",   # harmless variant, kept simple/passive on purpose
    "1' ORDER BY 100-- -",
]


def run_passive_detection(url, param_names, cookie_header=None, timeout=6):
    """
    Returns a list of finding dicts:
      {parameter_name, detection_method, payload_used, finding_classification}
    One dict per parameter tested (worst-case classification kept if
    multiple payloads for the same parameter trigger a signature).
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
                # Target unreachable — surface as its own classification rather
                # than silently reporting "clean".
                classification = "SCAN_ERROR"
                triggering_payload = f"(request failed: {exc})"
                break

            body_lower = resp.text.lower()
            if any(sig in body_lower for sig in ERROR_SIGNATURES):
                classification = "CONFIRMED_VULNERABLE"
                triggering_payload = payload
                break  # no need to try more payloads on this param

        results.append({
            "parameter_name": param,
            "detection_method": "PASSIVE_ERROR_PATTERN",
            "payload_used": triggering_payload,
            "finding_classification": classification,
        })

    return results


def _elapsed_ms(url, param, payload, headers, timeout):
    """Send one request and return (elapsed_ms, timed_out, error).

    A timeout is treated as a strong "delayed" signal rather than a failure:
    a working SLEEP() payload can push the response past the timeout. Other
    request errors (unreachable host, etc.) are returned as `error`.
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
    """Measure the target's normal response time for a parameter.

    Sends `samples` benign requests (a plain value, no injection) and returns
    {mean_response_ms, stddev_response_ms, sample_count}, or None if every
    request failed (target unreachable). This is the adaptive part: the delay
    threshold is derived from THIS target's live timings, not a fixed number.
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
        # pstdev (not stdev) so a single successful sample yields 0 rather than raising.
        "stddev_response_ms": statistics.pstdev(timings),
        "sample_count": len(timings),
    }


def run_active_time_based_detection(url, param_names, baseline, cookie_header=None):
    """Time-based detection for parameters passive detection left CLEAN.

    `baseline` is the dict returned by calibrate_baseline(). For each parameter,
    inject a delay payload and compare the response time against the baseline.
    A response is "delayed" when it exceeds:
        mean + BASELINE_STDDEV_MULTIPLIER * stddev + DELAY_MARGIN_MS

    Classification per parameter:
      - all ACTIVE_REPEATS requests delayed      -> CONFIRMED_VULNERABLE
      - some (but not all) repeats delayed        -> POSSIBLY_VULNERABLE
      - none delayed                              -> CLEAN
      - host became unreachable mid-test          -> SCAN_ERROR

    Returns a list of finding dicts in the same shape as run_passive_detection().
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

            # Probe once; only spend the extra repeats if the first looks delayed.
            elapsed, _timed_out, error = _elapsed_ms(
                url, param, payload, headers, ACTIVE_TIMEOUT)
            if error is not None:
                classification = "SCAN_ERROR"
                triggering_payload = f"(request failed: {error})"
                break
            if elapsed <= threshold_ms:
                continue  # this payload didn't delay; try the next one

            # First request was slow — repeat to check the delay is consistent.
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
                break  # confirmed; no need to try other payloads
            else:
                # Inconsistent — keep as a lead but keep trying other payloads
                # in case one delays consistently.
                classification = "POSSIBLY_VULNERABLE"
                triggering_payload = payload

        results.append({
            "parameter_name": param,
            "detection_method": "ACTIVE_TIME_BASED",
            "payload_used": triggering_payload,
            "finding_classification": classification,
        })

    return results
