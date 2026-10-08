from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from .. import db
from ..models import ScanTarget, VulnerabilityFinding, DetectionBaseline
from .detection import (
    run_passive_detection,
    calibrate_baseline,
    run_active_time_based_detection,
)

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


@scan_bp.route("/scan/new", methods=["GET", "POST"])
@login_required
def new_scan():
    if request.method == "POST":
        url = request.form["url"].strip()
        raw_params = request.form.get("parameters", "").strip()
        cookie_header = request.form.get("cookie", "").strip() or None
        param_names = [p.strip() for p in raw_params.split(",") if p.strip()]

        # Server-side check too — the HTML `required` attribute alone can be bypassed.
        if request.form.get("authorized") != "yes":
            flash("Confirm you own this target or have written permission to test it.", "error")
            return render_template("new_scan.html")

        if not url or not param_names:
            flash("A target URL and at least one parameter name are required.", "error")
            return render_template("new_scan.html")

        target = ScanTarget(
            initiated_by=current_user.user_id,
            url=url,
            parameters=raw_params,
            scan_status="RUNNING",
        )
        db.session.add(target)
        db.session.flush()  # get target.scan_id

        # Stage 1: passive error-pattern detection on every parameter.
        passive = run_passive_detection(url, param_names, cookie_header=cookie_header)
        findings_by_param = {f["parameter_name"]: f for f in passive}

        # Stage 2: escalate to active time-based detection only for parameters
        # passive left CLEAN (per the Activity Diagram: confirmed or errored
        # parameters are not re-tested). Needs an adaptive baseline first.
        clean_params = [f["parameter_name"] for f in passive
                        if f["finding_classification"] == "CLEAN"]
        if clean_params:
            base = calibrate_baseline(url, clean_params[0], cookie_header=cookie_header)
            if base is not None:
                db.session.add(DetectionBaseline(
                    scan_id=target.scan_id,
                    mean_response_ms=base["mean_response_ms"],
                    stddev_response_ms=base["stddev_response_ms"],
                    sample_count=base["sample_count"],
                ))
                active = run_active_time_based_detection(
                    url, clean_params, base, cookie_header=cookie_header)
                # Active result supersedes the passive CLEAN for these params.
                for f in active:
                    findings_by_param[f["parameter_name"]] = f

        for param in param_names:
            f = findings_by_param[param]
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

    return render_template("new_scan.html")


@scan_bp.route("/scan/<int:scan_id>")
@login_required
def results(scan_id):
    target = ScanTarget.query.get_or_404(scan_id)
    if target.initiator.org_id != current_user.org_id:
        flash("You can only view scans from your own organization.", "error")
        return redirect(url_for("scan.dashboard"))
    findings = VulnerabilityFinding.query.filter_by(scan_id=scan_id).all()
    return render_template("results.html", target=target, findings=findings)
