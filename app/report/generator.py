"""
Builds the report text (plain language + data protection guidance) for a scan.

Limitations: this just fills in a template, it's not a proper legal/compliance
engine. You get one paragraph per confirmed finding that talks about data
protection obligations in general terms. It still doesn't have the stuff the
proposal asks for i.e. Kenya's Data Protection Act (2019) Section 43, the
72-hour ODPC notification and the penalty range. TODO add these.
(Section 3.2.3 of my proposal says "UK Data Protection Act" by mistake, it
should be Kenya's DPA like the rest of the document.)
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
    """Takes a list of VulnerabilityFinding rows and returns the report text."""
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
