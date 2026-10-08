# SQL Injection Detection & Remediation Training Platform

Flask web app that scans a target for SQL injection, reports findings with
data-protection guidance, and trains developers to fix them - then re-tests
the fix against the live target before marking it resolved.

## Current status
Built: registration/login (multi-tenant), passive error-pattern detection,
report page, training sandbox, closed-loop re-test verification.

Not built yet: active time-based detection, Boolean-based blind detection,
adaptive baseline calibration, password reset, DVWA auto-login.

## Run locally
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python run.py                   # then open http://localhost:5000/register
```

## Test target (DVWA)
```bash
docker run -d -p 80:80 vulnerables/web-dvwa
```
Log into DVWA in your browser (admin / password), click "Create / Reset Database",
set security level to Low, then copy the Cookie header from your browser's
devtools into the scan form. Use `http://localhost/vulnerabilities/sqli/?Submit=Submit`
as the target URL and `id` as the parameter (DVWA only runs the query when `Submit` is present).

Only scan systems you own or have written permission to test.
