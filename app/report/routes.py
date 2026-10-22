from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from .. import db
from ..models import ScanTarget, VulnerabilityFinding, ReportDocument
from .generator import build_report_text

# Blueprint for all report-related pages
report_bp = Blueprint("report", __name__)


# Show the latest report for a scan, creating one if none exists yet
@report_bp.route("/scan/<int:scan_id>/report")
@login_required
def view_report(scan_id):
    # Look up the scan (404 if missing)
    target = ScanTarget.query.get_or_404(scan_id)

    # Only the user who started the scan may view its report
    if target.initiated_by != current_user.user_id:
        flash("You can only view reports for scans you submitted.", "error")
        return redirect(url_for("scan.dashboard"))

    # Get the most recently generated report for this scan
    report = ReportDocument.query.filter_by(scan_id=scan_id).order_by(
        ReportDocument.generation_timestamp.desc()
    ).first()

    # No report yet: build one from the scan's findings and save it
    if report is None:
        findings = VulnerabilityFinding.query.filter_by(scan_id=scan_id).all()
        report = ReportDocument(
            scan_id=scan_id,
            regulatory_guidance_text=build_report_text(findings),
        )
        db.session.add(report)
        db.session.commit()

    return render_template("report_view.html", target=target, report=report)


# Build a fresh report for a scan (keeps older reports as history)
@report_bp.route("/scan/<int:scan_id>/report/regenerate", methods=["POST"])
@login_required
def regenerate_report(scan_id):
    # Look up the scan (404 if missing)
    target = ScanTarget.query.get_or_404(scan_id)

    # Only the user who started the scan may regenerate its report
    if target.initiated_by != current_user.user_id:
        flash("You can only regenerate reports for scans you submitted.", "error")
        return redirect(url_for("scan.dashboard"))

    # Create a new report from the current findings and save it
    findings = VulnerabilityFinding.query.filter_by(scan_id=scan_id).all()
    report = ReportDocument(scan_id=scan_id, regulatory_guidance_text=build_report_text(findings))
    db.session.add(report)
    db.session.commit()

    # Send the user back to the report page, which now shows the new report
    return redirect(url_for("report.view_report", scan_id=scan_id))
