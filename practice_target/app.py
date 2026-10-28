"""
A deliberately-vulnerable practice target: a pretend "SACCO member portal".

This is NOT part of the CFDS platform - it's a separate little web app that
plays the role DVWA plays, but bundled with the project so the whole
detect -> report -> train -> verify loop can be demonstrated on one machine with
no Docker. It runs on port 8000 so the main app can stay on 5000.

It has a member-lookup page with a classic SQL injection hole in the `id`
parameter. A "mode" cookie flips the same endpoint between:
  - vulnerable (default): the value is concatenated straight into the SQL, so a
    single quote breaks it and `' OR '1'='1` dumps every member's record;
  - secure: the value is bound through a parameter and validated, so nothing
    injects - this is what a fixed version looks like.

That toggle is what lets the sandbox's live re-test actually reach
VERIFIED_RESOLVED: scan it vulnerable (CONFIRMED), then re-test with a
`mode=secure` cookie (CLEAN). DVWA can't do this because you can't patch it.

SAFETY: this app intentionally contains a vulnerability. Only ever run it
locally, for training. Never deploy it or expose it to a network.
"""
import os
import sqlite3

from flask import Flask, request, redirect, make_response, render_template_string

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "portal.db")

# a handful of fake SACCO members - the "personal data" an attacker would reach
MEMBERS = [
    (1, "Amina Were",       "12345678", "0712000001", 15400.00),
    (2, "Brian Otieno",     "23456789", "0712000002", 8200.50),
    (3, "Catherine Njeri",  "34567890", "0712000003", 94300.00),
    (4, "David Kiprono",    "45678901", "0712000004", 1200.00),
    (5, "Esther Wambui",    "56789012", "0712000005", 56780.25),
    (6, "Faisal Hassan",    "67890123", "0712000006", 300.00),
    (7, "Grace Akinyi",     "78901234", "0712000007", 41000.00),
    (8, "Henry Mutua",      "89012345", "0712000008", 7650.75),
]


def init_db():
    """Build a fresh members table each time the portal starts."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS members")
    conn.execute(
        "CREATE TABLE members (member_id INTEGER PRIMARY KEY, full_name TEXT, "
        "national_id TEXT, phone TEXT, savings_balance REAL)"
    )
    conn.executemany("INSERT INTO members VALUES (?, ?, ?, ?, ?)", MEMBERS)
    conn.commit()
    conn.close()


def _mode():
    """Which mode we're in: 'secure' only if the cookie says so, else vulnerable."""
    return "secure" if request.cookies.get("mode") == "secure" else "vulnerable"


PAGE = """
<!doctype html><html><head><meta charset="utf-8"><title>Unity SACCO - Member Portal</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body>
<nav class="navbar navbar-dark bg-success mb-3"><div class="container">
  <span class="navbar-brand">Unity SACCO — Member Portal</span>
  <span class="text-white">Mode:
    <span class="badge bg-{{ 'secondary' if mode=='secure' else 'danger' }}">{{ mode }}</span>
  </span>
</div></nav>
<div class="container">
  <div class="alert alert-warning">
    <strong>Practice target — deliberately insecure.</strong> This stands in for a
    small SACCO's member-lookup page. Use it only for local training with the CFDS scanner.
    <a href="{{ url_for('toggle') }}" class="btn btn-sm btn-outline-dark ms-2">
      Switch to {{ 'vulnerable' if mode=='secure' else 'secure' }} mode</a>
  </div>

  <h4>Look up a member</h4>
  <form method="get" action="{{ url_for('members') }}" class="row g-2 col-md-6">
    <div class="col-auto"><input class="form-control" name="id" placeholder="member id, e.g. 1"></div>
    <div class="col-auto"><button class="btn btn-success" name="Submit" value="Submit">Look up</button></div>
  </form>
  {{ body|safe }}
</div></body></html>
"""

RESULTS = """
{% if error %}
<div class="alert alert-danger mt-3"><strong>Database error:</strong><pre class="mb-0">{{ error }}</pre></div>
{% elif rows is not none %}
<table class="table table-striped mt-3">
  <thead><tr><th>ID</th><th>Name</th><th>National ID</th><th>Phone</th><th>Savings (KES)</th></tr></thead>
  <tbody>
  {% for r in rows %}<tr><td>{{ r[0] }}</td><td>{{ r[1] }}</td><td>{{ r[2] }}</td><td>{{ r[3] }}</td><td>{{ '%.2f'|format(r[4]) }}</td></tr>
  {% else %}<tr><td colspan="5">No member found.</td></tr>{% endfor %}
  </tbody>
</table>
{% endif %}
"""


@app.route("/")
def home():
    return render_template_string(PAGE, mode=_mode(), body="")


@app.route("/toggle")
def toggle():
    """Flip the mode cookie, so you can show both the vulnerable and fixed paths."""
    new_mode = "vulnerable" if _mode() == "secure" else "secure"
    resp = make_response(redirect(request.referrer or "/"))
    resp.set_cookie("mode", new_mode)
    return resp


@app.route("/members")
def members():
    raw = request.args.get("id")
    if raw is None:
        return render_template_string(PAGE, mode=_mode(), body="")

    conn = sqlite3.connect(DB_PATH)
    error = None
    rows = None
    try:
        if _mode() == "secure":
            # the fix: value is bound, and we only accept a number anyway
            if not raw.isdigit():
                rows = []  # rejected, no error leaked
            else:
                rows = conn.execute(
                    "SELECT member_id, full_name, national_id, phone, savings_balance "
                    "FROM members WHERE member_id = ?", (raw,)).fetchall()
        else:
            # the bug: the value is pasted straight into the SQL string
            query = ("SELECT member_id, full_name, national_id, phone, savings_balance "
                     "FROM members WHERE member_id = '" + raw + "'")
            rows = conn.execute(query).fetchall()
    except sqlite3.OperationalError as exc:
        # show the error the way a debug-mode app would - this is the signature
        # the scanner's passive detection looks for
        error = "sqlite3.OperationalError: " + str(exc)
    finally:
        conn.close()

    body = render_template_string(RESULTS, rows=rows, error=error)
    return render_template_string(PAGE, mode=_mode(), body=body)


if __name__ == "__main__":
    init_db()
    # threaded so the scanner's baseline/timing requests don't queue up
    app.run(port=8000, debug=False, threaded=True)
