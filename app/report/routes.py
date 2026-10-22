from flask import Blueprint, render_template, redirect, url_for, flash, request, Response
from flask_login import login_required, current_user

from .. import db
from ..models import ScanTarget, VulnerabilityFinding, ReportDocument
from .generator import build_report_text, AUDIENCES, AUDIENCE_LABELS
from .pdf import build_pdf

# Blueprint for all report-related pages
report_bp = Blueprint("report", __name__)


# Read the audience from the query string / form, falling back to MANAGEMENT
def _audience_from(source):
    audience = source.get("audience", "MANAGEMENT")
    return audience if audience in AUDIENCES else "MANAGEMENT"


# Look up a scan the current user may see reports for, or None
def _own_scan(scan_id):
    target = ScanTarget.query.get_or_404(scan_id)
    if target.initiated_by != current_user.user_id:
        return None
    return target


# Build a fresh report for one audience from the scan's current findings
def _new_report(scan_id, audience):
    findings = VulnerabilityFinding.query.filter_by(scan_id=scan_id).all()
    report = ReportDocument(
        scan_id=scan_id,
        target_audience=audience,
        regulatory_guidance_text=build_report_text(findings, audience),
    )
    db.session.add(report)
    return report


# Latest report for a scan and audience, creating one if none exists yet
def _latest_report(scan_id, audience):
    report = ReportDocument.query.filter_by(scan_id=scan_id, target_audience=audience).order_by(
        ReportDocument.generation_timestamp.desc()
    ).first()
    if report is None:
        report = _new_report(scan_id, audience)
        db.session.commit()
    return report


# Show the latest report for a scan, for the chosen audience
@report_bp.route("/scan/<int:scan_id>/report")
@login_required
def view_report(scan_id):
    # Only the user who started the scan may view its report
    target = _own_scan(scan_id)
    if target is None:
        flash("You can only view reports for scans you submitted.", "error")
        return redirect(url_for("scan.dashboard"))

    audience = _audience_from(request.args)
    report = _latest_report(scan_id, audience)
    return render_template("report_view.html", target=target, report=report,
                           audience=audience, audiences=AUDIENCES, labels=AUDIENCE_LABELS)


# Build a fresh report for one audience, or for all of them (keeps older reports as history)
@report_bp.route("/scan/<int:scan_id>/report/regenerate", methods=["POST"])
@login_required
def regenerate_report(scan_id):
    # Only the user who started the scan may regenerate its report
    target = _own_scan(scan_id)
    if target is None:
        flash("You can only regenerate reports for scans you submitted.", "error")
        return redirect(url_for("scan.dashboard"))

    if request.form.get("audience") == "ALL":
        for audience in AUDIENCES:
            _new_report(scan_id, audience)
        db.session.commit()
        flash("Generated a report for every audience.", "success")
        return redirect(url_for("report.view_report", scan_id=scan_id))

    audience = _audience_from(request.form)
    _new_report(scan_id, audience)
    db.session.commit()
    return redirect(url_for("report.view_report", scan_id=scan_id, audience=audience))


# Print-friendly page (no navigation) - the browser's "Save as PDF" turns it into a PDF
@report_bp.route("/scan/<int:scan_id>/report/print")
@login_required
def print_report(scan_id):
    target = _own_scan(scan_id)
    if target is None:
        flash("You can only view reports for scans you submitted.", "error")
        return redirect(url_for("scan.dashboard"))

    audience = _audience_from(request.args)
    report = _latest_report(scan_id, audience)
    return render_template("report_print.html", target=target, report=report,
                           audience=audience, audience_label=AUDIENCE_LABELS[audience])


# Download the report as a plain-text file that opens anywhere
@report_bp.route("/scan/<int:scan_id>/report/download")
@login_required
def download_report(scan_id):
    target = _own_scan(scan_id)
    if target is None:
        flash("You can only download reports for scans you submitted.", "error")
        return redirect(url_for("scan.dashboard"))

    audience = _audience_from(request.args)
    report = _latest_report(scan_id, audience)
    body = (
        f"SQL injection scan report - scan #{target.scan_id}\n"
        f"Audience: {AUDIENCE_LABELS[audience]}\n"
        f"Target: {target.url}\n"
        f"Generated: {report.generation_timestamp.strftime('%Y-%m-%d %H:%M')} UTC\n\n"
        f"{report.regulatory_guidance_text}\n"
    )
    filename = f"scan{target.scan_id}_{audience.lower()}_report.txt"
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


# Download the report as a real PDF file (built server-side, no print dialog needed)
@report_bp.route("/scan/<int:scan_id>/report/pdf")
@login_required
def download_pdf(scan_id):
    target = _own_scan(scan_id)
    if target is None:
        flash("You can only download reports for scans you submitted.", "error")
        return redirect(url_for("scan.dashboard"))

    audience = _audience_from(request.args)
    report = _latest_report(scan_id, audience)
    pdf = build_pdf(
        f"SQL injection scan report - {AUDIENCE_LABELS[audience]}",
        [f"Scan #{target.scan_id}   Target: {target.url}",
         f"Generated: {report.generation_timestamp.strftime('%Y-%m-%d %H:%M')} UTC"],
        report.regulatory_guidance_text,
    )
    filename = f"scan{target.scan_id}_{audience.lower()}_report.pdf"
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})
