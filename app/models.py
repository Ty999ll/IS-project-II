"""
Database models for the project. These are supposed to match the Database Schema
and Class Diagram in docs/ field for field.
NOTE: if I change a field here I need to update the diagrams as well (and the
other way round) otherwise they won't match anymore.
"""
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db


# An institution (a microfinance or SACCO) that signs up. The first person to
# register with a new org name creates it; everyone else with that name joins it.
class Organization(db.Model):
    __tablename__ = "organization"
    org_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    sector = db.Column(db.String(80))                        # e.g. SACCO / Bank, picked at registration
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # one organization has many users (backref lets me write user.organization)
    users = db.relationship("User", backref="organization", lazy=True)


# A person with a login. role is IT_GENERALIST or DEVELOPER (not enforced yet).
class User(UserMixin, db.Model):
    __tablename__ = "user"
    user_id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.org_id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="IT_GENERALIST")  # or 'DEVELOPER'

    scan_targets = db.relationship("ScanTarget", backref="initiator", lazy=True)

    # Flask-Login calls get_id(). UserMixin's version looks for a column called 'id'
    # but my primary key is 'user_id' so I had to override it here
    def get_id(self):
        return str(self.user_id)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# One scan the user ran: the URL they entered, which fields got tested, and how
# far along it is. Every scan belongs to the user (and so the org) that ran it.
class ScanTarget(db.Model):
    __tablename__ = "scan_target"
    scan_id = db.Column(db.Integer, primary_key=True)
    initiated_by = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    parameters = db.Column(db.Text)          # the tested fields, stored as JSON (see serialize_fields)
    scan_status = db.Column(db.String(20), default="PENDING")  # PENDING / RUNNING / COMPLETE
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # one scan has many findings (one per field it tested)
    findings = db.relationship("VulnerabilityFinding", backref="scan_target", lazy=True)


# The result for one tested field: how it was classified, by which method, and
# where its remediation stands. This is the heart of what a scan produces.
class VulnerabilityFinding(db.Model):
    __tablename__ = "vulnerability_finding"
    finding_id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_target.scan_id"), nullable=False)
    parameter_name = db.Column(db.String(120))
    detection_method = db.Column(db.String(30))          # PASSIVE_ERROR_PATTERN / ACTIVE_TIME_BASED / BOOLEAN_BLIND
    vulnerability_type = db.Column(db.String(30), default="SQLI")  # only SQLI for now, XSS might be added later
    finding_classification = db.Column(db.String(30))    # CONFIRMED_VULNERABLE / POSSIBLY_VULNERABLE / CLEAN
    payload_used = db.Column(db.Text)
    remediation_status = db.Column(db.String(20), default="UNRESOLVED")
    verified_at = db.Column(db.DateTime, nullable=True)


# these tables were added early so I wouldn't have to change the schema later
# (DetectionBaseline is used by the time-based scan now, the others are only partly used)

# How long the target normally takes to answer, measured per scan. The
# time-based detection uses this so "slow" is judged against THIS target, not a
# fixed number (this is the "adaptive baseline" from additions.txt).
class DetectionBaseline(db.Model):
    __tablename__ = "detection_baseline"
    baseline_id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_target.scan_id"), nullable=False)
    mean_response_ms = db.Column(db.Float)       # average normal response time
    stddev_response_ms = db.Column(db.Float)     # how much that time wobbles
    sample_count = db.Column(db.Integer)


# One training exercise tied to a finding: the vulnerable snippet shown, the
# model fix, what the developer submitted, and their score.
class TrainingChallenge(db.Model):
    __tablename__ = "training_challenge"
    challenge_id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("vulnerability_finding.finding_id"), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.user_id"))
    challenge_type = db.Column(db.String(30))
    vulnerable_code_snippet = db.Column(db.Text)
    correct_parameterized_solution = db.Column(db.Text)
    developer_response = db.Column(db.Text)      # what the developer typed in
    score = db.Column(db.Integer)                # 0 fail / 50 still vulnerable / 100 verified fixed


# A generated report. The same scan can have several (one per audience, and a
# new row each time it's regenerated), so this is where the report text lives.
class ReportDocument(db.Model):
    __tablename__ = "report_document"
    report_id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_target.scan_id"), nullable=False)
    # roadmap item 12: the same findings produce one report per reader. Added
    # field (no existing field renamed/removed). ScanTarget -> ReportDocument is
    # now 1:many (one report per audience); diagrams to be updated to match.
    target_audience = db.Column(db.String(30), default="MANAGEMENT")  # MANAGEMENT / HR_DATA_PROTECTION / IT_GENERALIST / DEVELOPER
    regulatory_guidance_text = db.Column(db.Text)
    generation_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
