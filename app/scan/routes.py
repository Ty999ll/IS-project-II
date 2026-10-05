from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from .. import db
from ..models import ScanTarget, VulnerabilityFinding
from .detection import run_passive_detection

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

        findings = run_passive_detection(url, param_names, cookie_header=cookie_header)
        for f in findings:
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
    findings = VulnerabilityFinding.query.filter_by(scan_id=scan_id).all()
    return render_template("results.html", target=target, findings=findings)
