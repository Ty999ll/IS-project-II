from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from .. import db
from ..models import ScanTarget, VulnerabilityFinding, DetectionBaseline
from .detection import (
    run_passive_detection,
    calibrate_baseline,
    run_active_time_based_detection,
    run_boolean_blind_detection,
    discover_fields,
    serialize_fields,
    load_scan_fields,
    authenticated_cookie_header,
    session_still_valid,
    siblings_by_param,
    _parse_cookie_header,
    _cookie_header_from,
)
from . import target_sessions

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
        db.session.flush()  # so target.scan_id is set

        # Each field's sibling form fields (Submit button, hidden tokens, other
        # inputs), resubmitted with every probe so a Submit-gated form (DVWA
        # Medium/High) actually runs the query instead of looking CLEAN.
        sibs = siblings_by_param(fields)

        # Fields can be submitted by GET or POST, so run detection one method
        # group at a time (baseline calibration and payload submission have to
        # match how the field is actually sent).
        findings_by_param = {}
        for method in ("GET", "POST"):
            group = [f["name"] for f in fields if f["method"] == method]
            if not group:
                continue

            # Stage 1 - passive error pattern detection on this group
            passive = run_passive_detection(
                url, group, cookie_header=cookie_header, method=method, siblings=sibs)
            for f in passive:
                findings_by_param[f["parameter_name"]] = f

            # Stage 2 - time based detection for the params passive left CLEAN
            # (same escalation as the Activity Diagram). Calibrate first.
            clean_params = [f["parameter_name"] for f in passive
                            if f["finding_classification"] == "CLEAN"]
            if clean_params:
                base = calibrate_baseline(
                    url, clean_params[0], cookie_header=cookie_header, method=method,
                    extra=sibs.get(clean_params[0], {}))
                if base is not None:
                    db.session.add(DetectionBaseline(
                        scan_id=target.scan_id,
                        mean_response_ms=base["mean_response_ms"],
                        stddev_response_ms=base["stddev_response_ms"],
                        sample_count=base["sample_count"],
                    ))
                    active = run_active_time_based_detection(
                        url, clean_params, base, cookie_header=cookie_header, method=method,
                        siblings=sibs)
                    for f in active:  # replace the passive CLEAN with the active result
                        findings_by_param[f["parameter_name"]] = f

            # Stage 3 - Boolean-based blind for the params still CLEAN after
            # time-based (the third technique; Activity Diagram escalation).
            still_clean = [p for p, f in findings_by_param.items()
                           if p in group and f["finding_classification"] == "CLEAN"]
            if still_clean:
                blind = run_boolean_blind_detection(
                    url, still_clean, cookie_header=cookie_header, method=method, siblings=sibs)
                for f in blind:
                    findings_by_param[f["parameter_name"]] = f

        for field in fields:
            f = findings_by_param[field["name"]]
            db.session.add(VulnerabilityFinding(
                scan_id=target.scan_id,
                parameter_name=f["parameter_name"],
                detection_method=f["detection_method"],
                finding_classification=f["finding_classification"],
                payload_used=f["payload_used"],
            ))

        target.scan_status = "COMPLETE"
        db.session.commit()

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
