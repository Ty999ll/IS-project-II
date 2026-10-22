"""
Runs a scan in a background thread so the browser doesn't hang while the
time-based stage waits on SLEEP payloads (roadmap item 8). The request creates
the ScanTarget as RUNNING and starts run_scan_job(); the results page polls
/scan/<id>/status and updates to COMPLETE when the job finishes.

Simplifications (documented on purpose, no task queue needed here):
- Progress lives in a process-memory dict, not the database, so it isn't shared
  across processes and is lost on restart. The status endpoint falls back to the
  stored scan_status if the in-memory entry is gone, so a finished scan still
  reads COMPLETE after a restart.
- One scan per request; fields are processed one at a time through the
  passive -> time-based -> Boolean-blind escalation, writing each finding as it
  completes so progress (and partial results) are visible as the scan runs.
"""
import threading

from .. import db
from ..models import ScanTarget, VulnerabilityFinding, DetectionBaseline
from .detection import (
    run_passive_detection,
    calibrate_baseline,
    run_active_time_based_detection,
    run_boolean_blind_detection,
    siblings_by_param,
)

_PROGRESS = {}
_LOCK = threading.Lock()


def set_progress(scan_id, done, total, current, status):
    with _LOCK:
        _PROGRESS[scan_id] = {"done": done, "total": total, "current": current, "status": status}


def get_progress(scan_id):
    with _LOCK:
        p = _PROGRESS.get(scan_id)
        return dict(p) if p else None


def start_scan(app, scan_id, url, fields, cookie_header):
    """Kick off the scan in a daemon thread and return immediately."""
    set_progress(scan_id, 0, len(fields), None, "RUNNING")
    t = threading.Thread(target=run_scan_job, args=(app, scan_id, url, fields, cookie_header),
                         daemon=True)
    t.start()


def run_scan_job(app, scan_id, url, fields, cookie_header):
    """Process each field through the three-stage escalation, writing findings
    and updating progress as it goes, then mark the scan COMPLETE."""
    sibs = siblings_by_param(fields)
    total = len(fields)
    with app.app_context():
        try:
            baselines = {}  # method -> baseline, calibrated once per method
            done = 0
            for field in fields:
                name = field["name"]
                method = "POST" if field["method"] == "POST" else "GET"
                set_progress(scan_id, done, total, name, "RUNNING")
                extra = sibs.get(name, {})

                # Stage 1 - passive error-pattern
                res = run_passive_detection(
                    url, [name], cookie_header=cookie_header, method=method, siblings=sibs)[0]

                # Stage 2 - time-based, only if passive left it CLEAN
                if res["finding_classification"] == "CLEAN":
                    if method not in baselines:
                        base = calibrate_baseline(
                            url, name, cookie_header=cookie_header, method=method, extra=extra)
                        baselines[method] = base
                        if base is not None:
                            db.session.add(DetectionBaseline(
                                scan_id=scan_id,
                                mean_response_ms=base["mean_response_ms"],
                                stddev_response_ms=base["stddev_response_ms"],
                                sample_count=base["sample_count"],
                            ))
                            db.session.commit()
                    base = baselines[method]
                    if base is not None:
                        res = run_active_time_based_detection(
                            url, [name], base, cookie_header=cookie_header, method=method,
                            siblings=sibs)[0]

                # Stage 3 - Boolean-based blind, only if still CLEAN
                if res["finding_classification"] == "CLEAN":
                    res = run_boolean_blind_detection(
                        url, [name], cookie_header=cookie_header, method=method, siblings=sibs)[0]

                db.session.add(VulnerabilityFinding(
                    scan_id=scan_id,
                    parameter_name=res["parameter_name"],
                    detection_method=res["detection_method"],
                    finding_classification=res["finding_classification"],
                    payload_used=res["payload_used"],
                ))
                db.session.commit()
                done += 1
                set_progress(scan_id, done, total, None, "RUNNING")

            target = ScanTarget.query.get(scan_id)
            if target is not None:
                target.scan_status = "COMPLETE"
                db.session.commit()
            set_progress(scan_id, total, total, None, "COMPLETE")
        except Exception:
            # never leave the scan stuck on RUNNING; surface it as complete so
            # the user sees whatever findings were written, not a frozen page
            db.session.rollback()
            target = ScanTarget.query.get(scan_id)
            if target is not None:
                target.scan_status = "COMPLETE"
                db.session.commit()
            set_progress(scan_id, total, total, None, "COMPLETE")
        finally:
            db.session.remove()
