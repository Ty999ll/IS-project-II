# Practice target — Unity SACCO member portal

A small, **deliberately vulnerable** web app bundled with the project so you can
demonstrate the whole CFDS loop (detect → report → train → verify) on one
machine, without Docker or DVWA.

> ⚠️ It contains a real SQL injection hole on purpose. Only run it locally for
> training. Never deploy it or put it on a network.

## Run it

```powershell
# from the project root, with the venv active (it only needs Flask)
python practice_target\app.py      # serves on http://localhost:8000
```

Leave the main CFDS app running on port 5000 at the same time.

## What it is

A pretend SACCO member-lookup page. The `id` parameter on `/members` is
injectable. A **mode** toggle (top-right of the portal) switches the same page
between two versions of the code:

- **vulnerable** (default): the id is concatenated straight into the SQL, so
  `'` breaks the query and `' OR '1'='1` returns **every member's** name,
  national ID, phone and savings balance — a live data-protection breach.
- **secure**: the id is bound through a parameter and validated, so nothing
  injects — this is what the fixed code looks like.

## Suggested demo

1. Start this portal and the CFDS app.
2. In CFDS, **New scan** → URL `http://localhost:8000/members` → Run scan.
   The `id` field comes back **CONFIRMED_VULNERABLE**.
3. Open the **report** (plain-language + Kenya DPA guidance), then the
   **sandbox**, and submit a parameterized fix.
4. To see the fix verified: in the sandbox re-test, paste the cookie
   `mode=secure` (or scan again after switching the portal to secure mode). The
   live re-test comes back clean and the finding becomes **VERIFIED_RESOLVED**.
5. To show a true negative, scan once with the cookie `mode=secure` from the
   start — the `id` field reads **CLEAN**.

This is the DVWA Low → Impossible flow, but in a target you control and that
tells the project's own microfinance story.
