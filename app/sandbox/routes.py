from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from .. import db
from ..models import VulnerabilityFinding, TrainingChallenge, ScanTarget, User
from .evaluation import evaluate_submission
from ..scan.detection import (run_passive_detection, field_method_for, session_still_valid,
                              siblings_for)
from ..scan import target_sessions

sandbox_bp = Blueprint("sandbox", __name__)

# This is just an example snippet. We can't see DVWA's actual source code for
# the parameter so this shows what the bug usually looks like, it's not the
# real vulnerable line (the template also says this)
ILLUSTRATIVE_SNIPPET = (
    "# Illustrative pattern for parameter '{param}' — not DVWA's actual source\n"
    "query = \"SELECT * FROM users WHERE {param} = '\" + request.args.get('{param}') + \"'\"\n"
    "cursor.execute(query)"
)

# the model parameterized fix for the illustrative snippet, stored on the
# challenge so there's a reference solution (roadmap item 6)
MODEL_SOLUTION = (
    "# Parameterized fix for '{param}' — the value is bound, not concatenated\n"
    "query = \"SELECT * FROM users WHERE {param} = %s\"\n"
    "cursor.execute(query, (request.args.get('{param}'),))"
)

# findings the sandbox offers training for: confirmed and possibly-vulnerable
# (item 6 - possibly-vulnerable findings get a challenge too, not just confirmed)
TRAINABLE = ("CONFIRMED_VULNERABLE", "POSSIBLY_VULNERABLE")


def _trainable_base(org_id):
    """All trainable findings for an organization (confirmed + possibly)."""
    return (
        VulnerabilityFinding.query
        .join(ScanTarget, VulnerabilityFinding.scan_id == ScanTarget.scan_id)
        .join(User, ScanTarget.initiated_by == User.user_id)
        .filter(
            VulnerabilityFinding.finding_classification.in_(TRAINABLE),
            User.org_id == org_id,
        )
    )


def _open_findings(org_id):
    """Trainable findings still needing work (not yet verified resolved)."""
    return (_trainable_base(org_id)
            .filter(VulnerabilityFinding.remediation_status != "VERIFIED_RESOLVED")
            .all())


def _progress(org_id):
    """(resolved, total) trainable findings, for the progress indicator."""
    total = _trainable_base(org_id).count()
    resolved = (_trainable_base(org_id)
                .filter(VulnerabilityFinding.remediation_status == "VERIFIED_RESOLVED")
                .count())
    return resolved, total


def _next_open_finding_id(org_id, exclude_id):
    """The next finding still to fix (for the 'next challenge' progression)."""
    for f in _open_findings(org_id):
        if f.finding_id != exclude_id:
            return f.finding_id
    return None


def _render_challenge(finding, target, ch):
    resolved, total = _progress(current_user.org_id)
    return render_template(
        "sandbox_challenge.html", finding=finding, target=target, challenge=ch,
        snippet=snippet_for(finding), saved_session=target_sessions.get_saved(target.url),
        score=ch.score, resolved=resolved, total=total,
        next_finding_id=_next_open_finding_id(current_user.org_id, finding.finding_id))


@sandbox_bp.route("/sandbox")
@login_required
def challenge_list():
    findings = _open_findings(current_user.org_id)
    resolved, total = _progress(current_user.org_id)
    return render_template("sandbox_list.html", findings=findings,
                           resolved=resolved, total=total)


# A plain-language lesson on SQL injection and how to fix it (roadmap item: the
# "training" half of the project). Static educational content, no data needed.
@sandbox_bp.route("/sandbox/learn")
@login_required
def learn():
    return render_template("sandbox_learn.html")


@sandbox_bp.route("/sandbox/finding/<int:finding_id>", methods=["GET", "POST"])
@login_required
def challenge(finding_id):
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    target = finding.scan_target
    if target.initiator.org_id != current_user.org_id:
        flash("You can only open challenges for findings from your own organization.", "error")
        return redirect(url_for("sandbox.challenge_list"))

    ch =TrainingChallenge.query.filter_by(finding_id=finding_id).first()
    # NOTE: there's only one challenge per finding, not one per developer, so if
    # two developers open the same finding they will overwrite each other's attempt.
    # It's ok for the demo with one developer but I should add the developer to
    # the lookup later if more people are going to use it at the same time.
    if ch is None:
        ch = TrainingChallenge(
            finding_id=finding_id,
            assigned_to=current_user.user_id,
            challenge_type="PARAMETERIZED_QUERY_FIX",
            # store the snippet and the model fix on the challenge (item 6), so
            # they're not just built on the fly / left unset
            vulnerable_code_snippet=snippet_for(finding),
            correct_parameterized_solution=MODEL_SOLUTION.format(param=finding.parameter_name),
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
            return _render_challenge(finding, target, ch)

        # use the login saved when the site was scanned, unless a cookie was pasted
        saved = target_sessions.get_saved(target.url)
        expired = False
        if not cookie_header and saved:
            if session_still_valid(target.url, saved["cookie"]):
                cookie_header = saved["cookie"]
            else:
                target_sessions.forget(target.url)
                flash("Your saved login to this site has expired. Run a new scan with the "
                      "login details (or paste a session cookie) to re-test.", "warning")
                expired = True

        if not cookie_header:
            if not expired:
                flash("Syntax looks parameterized. To re-test it against the live target "
                      "before it's marked resolved, log in to the site (run a scan with its "
                      "login details) or paste a session cookie.", "warning")
            return _render_challenge(finding, target, ch)

        # this is verifyRemediation() from the diagrams, re-test the same field on the live target
        # resubmitting the field's whole form (siblings), the same way the scan did
        method = field_method_for(target.parameters, finding.parameter_name, url=target.url)
        sibs = {finding.parameter_name: siblings_for(target.parameters, finding.parameter_name, url=target.url)}
        retest = run_passive_detection(
            target.url, [finding.parameter_name], cookie_header=cookie_header, method=method,
            siblings=sibs)
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
            db.session.commit()
            # progression: hand the developer their next challenge, or finish
            nxt = _next_open_finding_id(current_user.org_id, finding_id)
            if nxt is not None:
                flash("Fixed and verified (+100 points). Here's your next challenge.", "success")
                return redirect(url_for("sandbox.challenge", finding_id=nxt))
            flash("Fixed and verified (+100 points). All findings resolved — nice work!", "success")
            return redirect(url_for("sandbox.challenge_list"))

        db.session.commit()
        return redirect(url_for("sandbox.challenge_list"))

    return _render_challenge(finding, target, ch)


def snippet_for(finding):
    return ILLUSTRATIVE_SNIPPET.format(param=finding.parameter_name)
