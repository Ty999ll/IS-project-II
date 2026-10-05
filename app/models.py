"""
Data model — field-for-field matches Database_Schema.drawio / Class_Diagram.drawio.
Keep this file as the single source of truth: if you change a field here,
update the diagrams too (or vice versa) so the two never drift apart again.
"""
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db


class Organization(db.Model):
    __tablename__ = "organization"
    org_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    sector = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    users = db.relationship("User", backref="organization", lazy=True)


class User(UserMixin, db.Model):
    __tablename__ = "user"
    user_id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.org_id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="IT_GENERALIST")  # or 'DEVELOPER'

    scan_targets = db.relationship("ScanTarget", backref="initiator", lazy=True)

    # Flask-Login needs get_id(); UserMixin supplies it from primary key attr named 'id'
    # by default, so we alias explicitly since our PK is 'user_id' not 'id'.
    def get_id(self):
        return str(self.user_id)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ScanTarget(db.Model):
    __tablename__ = "scan_target"
    scan_id = db.Column(db.Integer, primary_key=True)
    initiated_by = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    parameters = db.Column(db.Text)          # comma-separated or JSON string of param names
    scan_status = db.Column(db.String(20), default="PENDING")  # PENDING / RUNNING / COMPLETE
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    findings = db.relationship("VulnerabilityFinding", backref="scan_target", lazy=True)


class VulnerabilityFinding(db.Model):
    __tablename__ = "vulnerability_finding"
    finding_id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_target.scan_id"), nullable=False)
    parameter_name = db.Column(db.String(120))
    detection_method = db.Column(db.String(30))          # PASSIVE_ERROR_PATTERN / ACTIVE_TIME_BASED / BOOLEAN_BLIND
    vulnerability_type = db.Column(db.String(30), default="SQLI")  # scaffolds future XSS class
    finding_classification = db.Column(db.String(30))    # CONFIRMED_VULNERABLE / POSSIBLY_VULNERABLE / CLEAN
    payload_used = db.Column(db.Text)
    remediation_status = db.Column(db.String(20), default="UNRESOLVED")
    verified_at = db.Column(db.DateTime, nullable=True)


# --- Not built in the first 30% slice, but declared now so nothing else has to change later ---

class DetectionBaseline(db.Model):
    __tablename__ = "detection_baseline"
    baseline_id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_target.scan_id"), nullable=False)
    mean_response_ms = db.Column(db.Float)
    stddev_response_ms = db.Column(db.Float)
    sample_count = db.Column(db.Integer)


class TrainingChallenge(db.Model):
    __tablename__ = "training_challenge"
    challenge_id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("vulnerability_finding.finding_id"), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.user_id"))
    challenge_type = db.Column(db.String(30))
    vulnerable_code_snippet = db.Column(db.Text)
    correct_parameterized_solution = db.Column(db.Text)
    developer_response = db.Column(db.Text)
    score = db.Column(db.Integer)


class ReportDocument(db.Model):
    __tablename__ = "report_document"
    report_id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_target.scan_id"), nullable=False)
    regulatory_guidance_text = db.Column(db.Text)
    generation_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
