from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from .. import db
from ..models import VulnerabilityFinding, TrainingChallenge, ScanTarget, User
from .evaluation import evaluate_submission
from ..scan.detection import run_passive_detection

sandbox_bp = Blueprint("sandbox", __name__)

# Illustrative only — we don't have access to DVWA's actual source file for a
# given parameter, so this is a representative "this is the shape of the bug"
# snippet, not the real vulnerable line. Said explicitly in the template too.
ILLUSTRATIVE_SNIPPET = (
    "# Illustrative pattern for parameter '{param}' — not DVWA's actual source\n"
    "query = \"SELECT * FROM users WHERE {param} = '\" + request.args.get('{param}') + \"'\"\n"
    "cursor.execute(query)"
)


@sandbox_bp.route("/sandbox")
@login_required
def challenge_list():
    findings = (
        VulnerabilityFinding.query
        .join(ScanTarget, VulnerabilityFinding.scan_id == ScanTarget.scan_id)
        .join(User, ScanTarget.initiated_by == User.user_id)
        .filter(
            VulnerabilityFinding.finding_classification == "CONFIRMED_VULNERABLE",
            User.org_id == current_user.org_id,
            VulnerabilityFinding.remediation_status != "VERIFIED_RESOLVED",
        )
        .all()
    )
    return render_template("sandbox_list.html", findings=findings)


@sandbox_bp.route("/sandbox/finding/<int:finding_id>", methods=["GET", "POST"])
@login_required
def challenge(finding_id):
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    target = finding.scan_target
    if target.initiator.org_id != current_user.org_id:
        flash("You can only open challenges for findings from your own organization.", "error")
        return redirect(url_for("sandbox.challenge_list"))

    ch =TrainingChallenge.query.filter_by(finding_id=finding_id).first()
    # Simplification: one challenge per finding, not per (finding, developer) pair —
    # if two developers open the same finding they'll share and overwrite the same
    # attempt. Fine for a first-slice single-developer demo; worth splitting out
    # (add developer to the lookup key) before multiple people use this concurrently.
    if ch is None:
        ch = TrainingChallenge(
            finding_id=finding_id,
            assigned_to=current_user.user_id,
            challenge_type="PARAMETERIZED_QUERY_FIX",
        )
        db.session.add(ch)
        db.session.commit()

    if request.method == "POST":
        code = request.form.get("solution", "")
        cookie_header = request.form.get("cookie", "").strip() or None
        ch.developer_response = code
        finding.remediation_status = "FIX_SUBMITTED"
        db.session.commit()

        passed, feedback = evaluate_submission(code)
        if not passed:
            ch.score = 0
            db.session.commit()
            flash(feedback, "error")
            return render_template("sandbox_challenge.html", finding=finding, target=target,
                                    challenge=ch, snippet=snippet_for(finding))

        if not cookie_header:
            flash("Syntax looks parameterized. Paste the DVWA session cookie too so this can "
                  "be re-tested against the live target before it's marked resolved.", "warning")
            return render_template("sandbox_challenge.html", finding=finding, target=target,
                                    challenge=ch, snippet=snippet_for(finding))

        # verifyRemediation() — re-test the exact field against the live target
        retest = run_passive_detection(target.url, [finding.parameter_name], cookie_header=cookie_header)
        still_vulnerable = retest[0]["finding_classification"] == "CONFIRMED_VULNERABLE"

        if still_vulnerable:
            finding.remediation_status = "STILL_VULNERABLE"
            ch.score = 50
            flash("Re-test against the live target still triggered a SQL error signature. "
                  "Flagged for re-review — not marked resolved.", "error")
        else:
            finding.remediation_status = "VERIFIED_RESOLVED"
            finding.verified_at = datetime.utcnow()
            ch.score = 100
            flash("Re-test against the live target came back clean. Marked VERIFIED_RESOLVED.", "success")

        db.session.commit()
        return redirect(url_for("sandbox.challenge_list"))

    return render_template("sandbox_challenge.html", finding=finding, target=target,
                            challenge=ch, snippet=snippet_for(finding))


def snippet_for(finding):
    return ILLUSTRATIVE_SNIPPET.format(param=finding.parameter_name)
