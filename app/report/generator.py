"""
Generates the plain-language + regulatory-guidance text for a scan's report.

Honesty note: this is a template-based generator, not a legal/compliance
engine. It produces a consistent, readable paragraph per confirmed finding
referencing the general shape of data-protection obligations. It does not yet
include what the proposal asks for: Kenya's Data Protection Act (2019)
Section 43, the 72-hour ODPC notification window, and the penalty range.
(Proposal section 3.2.3 says "UK Data Protection Act"; everywhere else it
cites Kenya's DPA, so treat that as a typo.)
"""

GUIDANCE_TEMPLATE = (
    "A SQL injection vulnerability was identified in the '{param}' parameter "
    "(detected via {method}). If exploited, this could allow unauthorized "
    "access to, modification of, or exfiltration of personal data held in "
    "the underlying database. Institutions handling personal data are "
    "generally expected to implement appropriate technical safeguards "
    "against this class of vulnerability under applicable data protection "
    "law; this finding should be remediated (parameterized queries / "
    "prepared statements) and verified before the affected endpoint is "
    "considered compliant."
)

METHOD_LABELS = {
    "PASSIVE_ERROR_PATTERN": "passive error-pattern analysis",
    "ACTIVE_TIME_BASED": "active time-based analysis",
    "BOOLEAN_BLIND": "Boolean-based blind analysis",
}


def build_report_text(findings):
    """findings: list of VulnerabilityFinding rows. Returns the full report body text."""
    confirmed = [f for f in findings if f.finding_classification == "CONFIRMED_VULNERABLE"]

    if not confirmed:
        return ("No confirmed SQL injection vulnerabilities were identified in this scan. "
                "This does not guarantee the target is free of injection flaws — only that "
                "the techniques run during this scan did not trigger a detectable signature.")

    sections = []
    for f in confirmed:
        method_label = METHOD_LABELS.get(f.detection_method, f.detection_method or "an automated technique")
        sections.append(GUIDANCE_TEMPLATE.format(param=f.parameter_name, method=method_label))

    header = f"{len(confirmed)} confirmed finding(s) require remediation:\n\n"
    return header + "\n\n".join(f"{i+1}. {s}" for i, s in enumerate(sections))
