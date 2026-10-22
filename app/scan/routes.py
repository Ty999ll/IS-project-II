from flask import (Blueprint, render_template, redirect, url_for, request, flash, jsonify,
                   current_app)
from flask_login import login_required, current_user

from .. import db
from ..models import ScanTarget, VulnerabilityFinding
from .detection import (
    discover_fields,
    serialize_fields,
    load_scan_fields,
    authenticated_cookie_header,
    session_still_valid,
    _parse_cookie_header,
    _cookie_header_from,
)
from . import target_sessions
from .jobs import start_scan, get_progress

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/")
def index():
    return redirect(url_for("scan.dashboard"))


@scan_bp.route("/dashboard")
@login_required
def dashboard():
    scans = (ScanTarget.query
             .filter_by(initiated_by=current_user.user_id)
             .order_by(ScanTarget.created_at.desc())
             .all())
    return render_template("dashboard.html", scans=scans)


# Render the new-scan form, showing saved target logins and keeping what was typed
def _scan_form(**prefill):
    return render_template("new_scan.html", saved_sessions=target_sessions.all_saved(),
                           prefill=prefill)


@scan_bp.route("/scan/new", methods=["GET", "POST"])
@login_required
def new_scan():
    if request.method == "POST":
        url = request.form["url"].strip()
        raw_params = request.form.get("parameters", "").strip()
        cookie_header = request.form.get("cookie", "").strip() or None
        login_url = request.form.get("login_url", "").strip()
        login_user = request.form.get("login_user", "").strip()
        login_pass = request.form.get("login_pass", "")
        prefill = {"url": url, "parameters": raw_params,
                   "login_url": login_url, "login_user": login_user}

        # check this on the server as well because the html `required` can be bypassed
        if request.form.get("authorized") != "yes":
            flash("Confirm you own this target or have written permission to test it.", "error")
            return _scan_form(**prefill)

        if not url:
            flash("A target URL is required.", "error")
            return _scan_form(**prefill)

        # Item 7: if login details were given, log in automatically and use that
        # authenticated session instead of (or merged with) a pasted cookie.
        # Pasting a cookie directly stays available as an advanced fallback.
        # Either way the session is remembered for this target site, so the next
        # scan of the same site needs no login at all.
        saved = target_sessions.get_saved(url)
        if login_url and login_user:
            cookie_header, login_error = authenticated_cookie_header(
                login_url, login_user, login_pass, extra_cookie=cookie_header)
            if login_error:
                flash(login_error, "error")
                return _scan_form(**prefill)
            target_sessions.save(url, cookie_header, login_url, login_user)
        elif saved:
            # reuse the saved login; anything pasted is merged in and wins
            # (e.g. to change DVWA's security level for this site)
            cookies = _parse_cookie_header(saved["cookie"])
            cookies.update(_parse_cookie_header(cookie_header))
            cookie_header = _cookie_header_from(cookies)
            if not session_still_valid(url, cookie_header):
                target_sessions.forget(url)
                flash("Your saved login to this site has expired. Enter the password "
                      "again to log back in.", "warning")
                prefill.update(login_url=saved["login_url"], login_user=saved["login_user"])
                return _scan_form(**prefill)
            target_sessions.save(url, cookie_header, saved["login_url"], saved["login_user"])
        elif cookie_header:
            target_sessions.save(url, cookie_header)

        # Work out which fields to test. If the user typed parameter names we
        # use those (manual fallback, all treated as GET). Otherwise we fetch
        # the page and discover the input fields automatically (item 1).
        if raw_params:
            fields = [{"name": p.strip(), "method": "GET", "action_url": url}
                      for p in raw_params.split(",") if p.strip()]
        else:
            discovery = discover_fields(url, cookie_header=cookie_header)
            fields = discovery["fields"]
            if not fields:
                msg = discovery["error"] or (
                    "No input fields were found on that page. Enter the parameter "
                    "names to test manually.")
                flash(msg, "error")
                return _scan_form(**prefill)

        target = ScanTarget(
            initiated_by=current_user.user_id,
            url=url,
            parameters=serialize_fields(fields),
            scan_status="RUNNING",
        )
        db.session.add(target)
        db.session.commit()  # persist the RUNNING scan before the thread picks it up

        # Run the detection (passive -> time-based -> Boolean-blind escalation) in
        # a background thread so the browser doesn't hang on the time-based waits;
        # the results page polls for progress and updates when it's COMPLETE
        # (roadmap item 8). Login and field discovery already ran synchronously
        # above, so their errors are shown on the form before we get here.
        start_scan(current_app._get_current_object(), target.scan_id, url, fields, cookie_header)

        return redirect(url_for("scan.results", scan_id=target.scan_id))

    return _scan_form()


# Forget the saved login for one target site
@scan_bp.route("/scan/target-session/forget", methods=["POST"])
@login_required
def forget_target_session():
    target_sessions.forget(request.form.get("origin", ""))
    flash("Saved login removed. The next scan of that site will ask you to log in.", "success")
    return redirect(url_for("scan.new_scan"))


@scan_bp.route("/scan/<int:scan_id>")
@login_required
def results(scan_id):
    target = ScanTarget.query.get_or_404(scan_id)
    if target.initiator.org_id != current_user.org_id:
        flash("You can only view scans from your own organization.", "error")
        return redirect(url_for("scan.dashboard"))
    findings = VulnerabilityFinding.query.filter_by(scan_id=scan_id).all()
    tested_fields = load_scan_fields(target.parameters, url=target.url)
    return render_template("results.html", target=target, findings=findings,
                           tested_fields=tested_fields)


# Progress of a running scan, polled by the results page (roadmap item 8)
@scan_bp.route("/scan/<int:scan_id>/status")
@login_required
def scan_status(scan_id):
    target = ScanTarget.query.get_or_404(scan_id)
    if target.initiator.org_id != current_user.org_id:
        return jsonify({"error": "forbidden"}), 403
    progress = get_progress(scan_id)
    if progress is None:
        # the in-memory entry is gone (e.g. after a restart); fall back to the DB
        progress = {"status": target.scan_status, "done": 0, "total": 0, "current": None}
    return jsonify(progress)
