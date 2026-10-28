# How the system works

A plain-English walkthrough of this project, written so you can follow the whole
thing end to end without having to read every line of code first. Keep it next
to the code — when a file is mentioned, open it and the comments there match
what's described here.

---

## 1. What this app is, in one paragraph

It's a web app (built with Flask) that an IT person at a small Kenyan
microfinance or SACCO can use to **find SQL-injection holes in a website**,
**read a plain-language report** about what that means and what the Data
Protection Act requires, and then **practise fixing the bug** in a built-in code
editor — after which the app **re-tests the real site** to confirm the fix
actually worked. Three jobs in one tool: *detect → explain → train & verify*.

---

## 2. The big picture

There are three main "modules", and they run in that order:

```
   You type a URL
        │
        ▼
 ┌──────────────┐     ┌──────────────┐     ┌─────────────────┐
 │  1. SCANNER  │ ──▶ │ 2. REPORT    │ ──▶ │ 3. TRAINING     │
 │  find the    │     │   GENERATOR  │     │    SANDBOX      │
 │  SQLi holes  │     │  explain them│     │  fix + re-test  │
 └──────────────┘     └──────────────┘     └─────────────────┘
```

Around those three sit the supporting pieces: **accounts & login** (so every
scan belongs to a real person and institution), an **organization dashboard**
(the overview the person lands on — posture, numbers and charts), and the
**database** (SQLite) that remembers everything. There's also a bundled
**practice target** (a deliberately-vulnerable app) you can point the scanner at.

The order matters: you can't write a report until the scanner has found
something, and you can't build a training challenge until you know what the
scanner found. That's why the code is split this way.

---

## 3. How to run it

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py            # then open http://localhost:5000/register
```

`run.py` is the starting gun. It calls `create_app()` (in `app/__init__.py`),
which builds the app, and then serves it on port 5000. The database file appears
by itself at `instance/cfds.db` the first time you run it.

> One gotcha: if you ever change a table in `app/models.py`, delete
> `instance/cfds.db` and restart. The app only *creates missing* tables, it
> never changes existing ones.

**Want something to scan?** The project bundles a deliberately-vulnerable target
so you don't need Docker/DVWA:

```powershell
python practice_target\app.py      # serves on http://localhost:8000
```

It's a pretend "SACCO member portal" with a real SQL-injection hole. Scan
`http://localhost:8000/members` from the main app. See
`practice_target/README.md` for the full demo (including how to reach
`VERIFIED_RESOLVED`).

---

## 4. The tech stack (and why these choices)

| Piece | What it does | Why it's here |
|------|---------------|---------------|
| **Flask** | the web framework (routes, pages) | light, no heavy setup — fits a small tool |
| **Flask-SQLAlchemy** | talks to the database using Python classes instead of SQL | safe (no hand-written SQL) and readable |
| **SQLite** | the database, a single file | zero setup, perfect for a prototype |
| **Flask-Login** | remembers who's logged in | standard, saves writing session code |
| **requests** | makes the outbound HTTP calls to the target site | gives exact control over each request |
| **Jinja2** | fills in the HTML templates | comes with Flask |
| **Bootstrap (CDN)** | makes the pages look decent | no build step, just a `<link>` |
| **CodeMirror (CDN)** | the code editor in the sandbox | in-browser editor with line numbers |
| **Chart.js (CDN)** | the dashboard charts | simple, good-looking charts, no build step |
| **itsdangerous** | signs the password-reset links | lets reset work without a database table |

No JavaScript build step, no database server, no migration tool — deliberately
simple so it runs anywhere with just Python and a browser.

---

## 5. The files, and what each one does

```
run.py                       starts the app on :5000
app/__init__.py              create_app(): wires up config, db, login, the routes
app/models.py                the database tables, as Python classes

app/auth/routes.py           register / login / logout / forgot+reset password
app/scan/routes.py           dashboard, the new-scan form, the results page, progress
app/scan/detection.py        the actual SQLi detection engine (the clever part)
app/scan/jobs.py             runs a scan in the background so the page doesn't freeze
app/scan/target_sessions.py  remembers your login to a target site between scans
app/report/routes.py         view / regenerate / download / print the report
app/report/generator.py      builds the report text (per audience, with DPA guidance)
app/report/pdf.py            turns the report text into a downloadable PDF
app/sandbox/routes.py        the challenge pages, the live re-test, and the Learn page
app/sandbox/evaluation.py    checks whether a submitted fix "looks" parameterized
app/templates/               the HTML pages (all extend base.html)

practice_target/app.py       a bundled, deliberately-vulnerable "SACCO portal" to scan
docs/                        the spec: proposal, diagrams, roadmap, evaluation harness
HOW_IT_WORKS.md              this file
```

A good way to read the code: **start at a route** (e.g. `scan.new_scan` in
`app/scan/routes.py`) and follow the function calls out from there.

---

## 6. The data model (the tables)

Everything lives in `app/models.py`. In plain English:

- **Organization** — an institution (a SACCO/microfinance). Has many users.
- **User** — a person who logs in. Belongs to one organization. Has a role
  (IT generalist or developer).
- **ScanTarget** — one scan someone ran: the URL, which fields were tested, and
  whether it's `PENDING` / `RUNNING` / `COMPLETE`. Belongs to the user who ran it.
- **VulnerabilityFinding** — the result for *one field* in a scan: how it was
  classified (`CONFIRMED_VULNERABLE` / `POSSIBLY_VULNERABLE` / `CLEAN`), which
  method found it, and where its fix stands (`remediation_status`).
- **DetectionBaseline** — how fast the target normally replies, measured during
  the scan, so "slow" is judged against *that* site (used by time-based detection).
- **TrainingChallenge** — one practice exercise tied to a finding: the vulnerable
  snippet, the model fix, what the developer typed, and their score.
- **ReportDocument** — a generated report. The same scan can have several (one
  per audience, plus a new one each time you regenerate).

How they connect:

```
Organization ──< User ──< ScanTarget ──< VulnerabilityFinding ──< TrainingChallenge
                                   │
                                   ├──< DetectionBaseline
                                   └──< ReportDocument
```

(`──<` means "has many".) So: an org has users, a user runs scans, a scan has
findings, and each finding can have a training challenge.

---

## 7. Follow a scan from start to finish

This is the most important journey. Here's what actually happens when you fill
in the new-scan form and press "Run scan":

1. **The form posts to `scan.new_scan`** (`app/scan/routes.py`).
2. **If you gave login details**, `authenticated_cookie_header()` logs in to the
   target first (handling its anti-CSRF token) and keeps the session cookie.
   That login is remembered for the site (`target_sessions.py`) so your next
   scan of the same site doesn't need it again.
3. **Field discovery** — `discover_fields()` fetches the target page and reads
   its forms to find every input box (plus any `?name=value` already in the URL).
   For each field it also notes the form's *other* fields (the Submit button,
   hidden tokens) so it can resubmit the whole form later — some sites only run
   their query when the Submit button is sent.
4. **The scan is saved as `RUNNING`** and a **background thread** starts
   (`jobs.start_scan`). The page redirects to the results page immediately, so
   your browser never hangs.
5. **The results page polls** `/scan/<id>/status` every 1.5 seconds and shows a
   progress bar. When the background job marks the scan `COMPLETE`, the page
   reloads to show the verdict.
6. **In the background**, `run_scan_job()` tests each field through the
   escalation chain (next section) and writes one `VulnerabilityFinding` per
   field as it goes.
7. **You open the report**, then the **sandbox** to fix anything that was found.

---

## 8. How detection actually works (the clever part)

All in `app/scan/detection.py`. For each field, it tries three techniques in
order, stopping as soon as one confirms the field is vulnerable. This "only
escalate if the last one found nothing" is the **escalation chain** from the
Activity Diagram.

**Stage 1 — Passive error-pattern detection** (`run_passive_detection`)
Sends a few odd characters (like a single quote `'`) and looks in the reply for
a database error message ("You have an error in your SQL syntax…"). If it sees
one, the field is `CONFIRMED_VULNERABLE`. This is the simplest and fastest check.

**Stage 2 — Active time-based detection** (`run_active_time_based_detection`)
Runs only if Stage 1 found nothing. First it measures how long the site normally
takes to reply (`calibrate_baseline` → a `DetectionBaseline`). Then it sends a
payload that tells the database to *pause* a few seconds (`SLEEP(5)`). If the
reply is much slower than normal — and consistently so across repeats — the
field is vulnerable even though no error showed. Judging "slow" against the
site's *own* measured speed is the **adaptive baseline** idea.

**Stage 3 — Boolean-based blind detection** (`run_boolean_blind_detection`)
Runs only if Stages 1 and 2 found nothing. Sends one request with a condition
that's always true (`AND 1=1`) and one that's always false (`AND 1=2`) and
compares the two replies. If the page changes between true and false (and the
"true" page matches the normal one), the input is reaching the database — even
with no error and no delay.

**The three verdicts:**
- `CONFIRMED_VULNERABLE` — a technique clearly confirmed it.
- `POSSIBLY_VULNERABLE` — a sign showed up but wasn't consistent (needs a human).
- `CLEAN` — nothing found (which doesn't *prove* it's safe, just that these
  checks didn't trip).

**Why "siblings" matter:** when the scanner tests one field, it also re-sends the
rest of that field's form (the Submit button, hidden fields). Without that, a
site that only runs its query when Submit is present would look falsely CLEAN.
This was a real bug we fixed.

---

## 9. The report module

`app/report/generator.py` turns the findings into words. The key ideas:

- **One report, four audiences.** The same findings are run through a different
  template for **Management**, **HR & Data Protection**, **IT**, and
  **Developer**. A manager gets business risk and decisions; a developer gets the
  payload and the exact fix. You pick the audience from a dropdown, or generate
  all four.
- **Data Protection Act content.** Every confirmed/possible finding carries the
  Kenya DPA (2019) Section 43 obligation: notify the ODPC within 72 hours, fines
  up to KES 5,000,000 or 1% of turnover.
- **It's template text, not AI.** The wording is fixed, so the same scan always
  produces the same report (which makes it testable).

`app/report/pdf.py` writes the report out as a real PDF file with no extra
library (it hand-writes the PDF structure). There's also a clean **print page**
(`report_print.html`) for "Save as PDF" from the browser, and a plain-text
download.

---

## 10. The training sandbox (and the "closed loop")

`app/sandbox/routes.py`. For each finding you can open a challenge:

1. It shows an **illustrative vulnerable snippet** for that field (not the
   target's real source — we can't see that) and a **CodeMirror editor**.
2. You type a **parameterized fix** and submit.
3. `evaluation.py` does a quick **regex check** — does the fix use a placeholder
   (`?`, `%s`, `:name`) instead of gluing the value into the string? If not, you
   get specific feedback and score 0.
4. If it looks right, the app does the **live re-test**: it runs passive
   detection again against the *real* field on the *real* site.
   - Still vulnerable → `STILL_VULNERABLE`, flagged for re-review (score 50).
   - Clean now → `VERIFIED_RESOLVED`, `verified_at` is stamped (score 100).
5. After a verified fix you're handed the **next challenge**, with a progress
   bar.

That re-test is the **closed loop**: the system doesn't just trust that you did
the exercise, it checks the live target before calling the finding fixed. (Note:
against DVWA on "Low" the re-test will stay `STILL_VULNERABLE`, because DVWA's
own code is never patched — set DVWA to "Impossible", or use the bundled
practice target's `mode=secure` cookie, to see the resolved path.)

**Learning support** (so this is real training, not just a quiz):
- A **Learn page** (`/sandbox/learn`) explains SQL injection and the fix in plain
  language, with before/after code in **Python, PHP and Java**.
- Each challenge has **progressive hints** and a **"show the model solution"**
  reveal (the stored `correct_parameterized_solution`).
- It's lightly **gamified**: your score shows, a progress bar tracks how many
  findings you've fixed, and a verified fix hands you the next challenge.

---

## 11. Why scans run in the background

A time-based scan can take tens of seconds (it deliberately waits for `SLEEP`
payloads). If that ran inside the web request, the browser would just hang and
look broken. So `app/scan/jobs.py` runs the detection in a **background thread**
and reports progress through a small in-memory record that the results page
polls. This is a deliberate prototype simplification (a real deployment would
use a proper task queue) — noted in the file's own comments.

---

## 12. The dashboard (what you land on)

After login you land on the **dashboard** (`scan.dashboard`). The top is an
**organization overview**: a traffic-light posture banner ("At risk" /
"Remediated" / "No issues found"), four quick numbers (scans run, vulnerable
fields, open to fix, % fixed & verified), and two charts drawn with Chart.js — a
doughnut of findings by result and a bar chart of which detection method caught
the problems. The numbers are computed in `_org_stats()` across everyone in your
organization. Below that is your own list of scans.

## 13. Accounts, organizations, and keeping scans private

`app/auth/routes.py` handles register / login / logout and the forgot/reset
password flow.

- **Registering with a new org name creates the organization**; registering with
  an existing name joins it.
- **Every scan belongs to the user (and so the org) that ran it**, and the routes
  check this: you can only open scans/findings from your own organization, and
  only the person who ran a scan can see its report.
- **Password reset** makes a **signed, time-limited link** (`itsdangerous`).
  There's no mail server in this project, so the link is shown on screen instead
  of emailed — in a real deployment it would go to the user's inbox.
- **Saved target logins** (`target_sessions.py`): once you log in to a target
  site, that session is remembered for this app-session so you can run several
  scans of the same site without re-entering it. It's cleared when you log out.

---

## 14. How it's tested

There's no formal test framework yet, but there is a **mock-target harness** at
`docs/evaluate_levels.py`. It stands up fake endpoints that imitate each DVWA
difficulty level, a Boolean-blind page, *and* a known-secure and known-insecure
custom control, then runs the *real* scanner against them and prints a pass/fail
table and a confusion matrix (true/false positives and negatives). It's how we
check the detection logic without needing DVWA running. `docs/evaluation.md`
explains the procedure and has the table to fill in from a real DVWA run.

For hands-on testing, the **bundled practice target** (`practice_target/`) lets
you run the whole thing live without Docker.

---

## 15. Known limitations (so you can speak to them)

These are deliberate boundaries for a prototype, not accidents:

- The fix-checker is **regex-based** and could be fooled — which is exactly why
  the **live re-test** exists as the real safety net.
- The scanner makes outbound requests to whatever URL you give it; it's meant for
  **lab targets you own** (local DVWA), confirmed by the authorization checkbox.
- The background scan uses in-memory progress and SQLite, which suit a single
  user but wouldn't scale to a hosted, multi-worker deployment.
- Roles exist but aren't enforced; there's no automated test suite yet.

These belong in the "Limitations and future work" part of the writeup.

---

## 16. Mini-glossary

- **SQL injection** — tricking a site into treating your input as database
  commands, so you can read or change data you shouldn't.
- **Parameterized query / prepared statement** — the fix: the value is sent
  *separately* from the query, so it can't be treated as code.
- **Payload** — the crafted input the scanner sends to test a field.
- **Passive / active detection** — passive = just read the normal response for
  error signs; active = send special payloads (delays, true/false tests) and
  watch what changes.
- **Baseline** — the target's normal response time, measured so the scanner can
  tell what "slow" means for that specific site.
- **Finding** — one tested field's result.
- **Closed-loop remediation** — fix it, then automatically re-test the live site
  before calling it resolved.
- **Blueprint** — Flask's way of grouping related routes (auth, scan, report,
  sandbox each have one).
- **Route** — a function that handles one URL (e.g. `/scan/new`).
- **Template** — an HTML file with `{{ }}` placeholders that Flask fills in.
