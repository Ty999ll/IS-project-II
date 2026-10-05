from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from .. import db
from ..models import ScanTarget, VulnerabilityFinding, ReportDocument
from .generator import build_report_text

report_bp = Blueprint("report", __name__)


@report_bp.route("/scan/<int:scan_id>/report")
@login_required
def view_report(scan_id):
    target = ScanTarget.query.get_or_404(scan_id)
    if target.initiated_by != current_user.user_id:
        flash("You can only view reports for scans you submitted.", "error")
        return redirect(url_for("scan.dashboard"))

    report = ReportDocument.query.filter_by(scan_id=scan_id).order_by(
        ReportDocument.generation_timestamp.desc()
    ).first()

    if report is None:
        findings = VulnerabilityFinding.query.filter_by(scan_id=scan_id).all()
        report = ReportDocument(
            scan_id=scan_id,
            regulatory_guidance_text=build_report_text(findings),
        )
        db.session.add(report)
        db.session.commit()

    return render_template("report_view.html", target=target, report=report)


@report_bp.route("/scan/<int:scan_id>/report/regenerate", methods=["POST"])
@login_required
def regenerate_report(scan_id):
    target = ScanTarget.query.get_or_404(scan_id)
    if target.initiated_by != current_user.user_id:
        flash("You can only regenerate reports for scans you submitted.", "error")
        return redirect(url_for("scan.dashboard"))

    findings = VulnerabilityFinding.query.filter_by(scan_id=scan_id).all()
    report = ReportDocument(scan_id=scan_id, regulatory_guidance_text=build_report_text(findings))
    db.session.add(report)
    db.session.commit()
    return redirect(url_for("report.view_report", scan_id=scan_id))
