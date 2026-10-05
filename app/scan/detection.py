"""
Passive error-pattern detection.

Sends a handful of classic SQL-injection probe payloads into each named
parameter and checks the response body for known database error signatures.
This is deliberately the SIMPLEST of the three detection techniques in the
proposal — active time-based and Boolean-based blind are NOT implemented
here; they're the next slice after this one is solid.

Limitation to be upfront about: DVWA needs an authenticated session +
a security-level cookie to actually respond to requests. For this first
slice, pass that in as a raw cookie header (copied from your browser's
devtools after logging into DVWA manually) via the "cookie" field on the
scan form, rather than automating DVWA's own login. Automating that is a
reasonable "next slice" task, not a blocker for demonstrating detection.
"""
import requests

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
