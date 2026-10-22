"""
Builds the report text for a scan.

Two things the roadmap asked for live here now:

- Item 4 (regulatory content): for every confirmed or possibly-vulnerable
  finding the report explains, in plain language, what the vulnerability is and
  what an attacker could do with it, and sets out the institution's obligations
  under Kenya's Data Protection Act (2019) - Section 43's 72-hour ODPC breach
  notification and the penalty range (up to KES 5,000,000 or 1% of annual
  turnover, whichever is lower).
- Item 12 (audience-specific reports): the same findings are rendered through a
  different template per reader - MANAGEMENT, HR_DATA_PROTECTION, IT_GENERALIST
  and DEVELOPER - so no manual rewriting is needed. Templates only, no
  AI-generated text, so the output is identical every time and testable.

Limitation: this is template-based guidance, not a legal/compliance engine, and
a CLEAN result does not prove the target is safe - only that the techniques run
during this scan found nothing.

(Proposal §3.2.3 says "UK Data Protection Act" by mistake; it should be Kenya's
DPA like the rest of the document.)
"""

AUDIENCES = ["MANAGEMENT", "HR_DATA_PROTECTION", "IT_GENERALIST", "DEVELOPER"]

AUDIENCE_LABELS = {
    "MANAGEMENT": "Management / Admin",
    "HR_DATA_PROTECTION": "HR & Data Protection",
    "IT_GENERALIST": "IT (generalist)",
    "DEVELOPER": "Developer",
}

METHOD_LABELS = {
    "PASSIVE_ERROR_PATTERN": "passive error-pattern analysis",
    "ACTIVE_TIME_BASED": "active time-based analysis",
    "BOOLEAN_BLIND": "Boolean-based blind analysis",
}

# the Kenya DPA obligation, stated once and reused where a reader needs it
DPA_OBLIGATION = (
    "Data-protection obligation (Kenya Data Protection Act, 2019): a SQL "
    "injection flaw that exposes personal data is a reportable risk. Under "
    "Section 43, where a breach is likely to harm the people whose data is "
    "affected, the Office of the Data Protection Commissioner (ODPC) must be "
    "notified within 72 hours of the institution becoming aware of it, and the "
    "affected members informed. Non-compliance can attract a penalty of up to "
    "KES 5,000,000, or in the case of an undertaking up to 1% of its annual "
    "turnover, whichever is lower."
)

CLEAN_TEXT = (
    "No confirmed SQL injection vulnerabilities were identified in this scan. "
    "Note: this does not prove the target is safe - it means only that the "
    "techniques run during this scan did not find a problem. Re-test after any "
    "change to the application."
)


def _severity(finding):
    return "High" if finding.finding_classification == "CONFIRMED_VULNERABLE" else "Medium"


def _status_label(finding):
    return (finding.remediation_status or "UNRESOLVED").replace("_", " ").title()


def _reportable(findings):
    """Confirmed first, then possibly-vulnerable - the findings a report covers."""
    confirmed = [f for f in findings if f.finding_classification == "CONFIRMED_VULNERABLE"]
    possible = [f for f in findings if f.finding_classification == "POSSIBLY_VULNERABLE"]
    return confirmed, possible


def _management_section(f, i):
    sev = _severity(f)
    kind = ("confirmed" if f.finding_classification == "CONFIRMED_VULNERABLE"
            else "possible (needs confirmation)")
    return (
        f"{i}. Field '{f.parameter_name}' - {sev} risk ({kind}).\n"
        "   What it means in business terms: an attacker could use this input to "
        "read or change member records held in the database - including personal "
        "and financial data - which is a fraud and data-breach risk for the "
        "institution.\n"
        f"   {DPA_OBLIGATION}\n"
        "   Decision needed: approve remediation of this endpoint and confirm "
        "whether an ODPC notification is required before the 72-hour window closes."
    )


def _hr_section(f, i):
    return (
        f"{i}. Field '{f.parameter_name}'.\n"
        "   Personal data at risk: this flaw could expose members' personal and "
        "financial records to unauthorised access or alteration.\n"
        f"   {DPA_OBLIGATION}\n"
        "   Staff action: ensure the data-protection officer is briefed, assess "
        "whether members must be notified, and schedule secure-coding awareness "
        "for the development team so this class of flaw is prevented in future."
    )


def _it_section(f, i):
    method_label = METHOD_LABELS.get(f.detection_method, f.detection_method or "an automated technique")
    return (
        f"{i}. Field '{f.parameter_name}' - {_severity(f)} risk.\n"
        f"   Detected via: {method_label}.\n"
        f"   Current remediation status: {_status_label(f)}.\n"
        "   Next steps: assign this finding to a developer to fix with "
        "parameterized queries, then re-test the exact field through the "
        "training sandbox before marking it resolved."
    )


def _developer_section(f, i):
    method_label = METHOD_LABELS.get(f.detection_method, f.detection_method or "an automated technique")
    payload = f.payload_used or "(no payload recorded)"
    return (
        f"{i}. Parameter '{f.parameter_name}' - SQL injection ({_severity(f)}).\n"
        f"   Detection method: {method_label}.\n"
        f"   Triggering payload: {payload}\n"
        "   Vulnerable pattern: the parameter value is concatenated straight into "
        "the SQL string.\n"
        "   Fix: use a parameterized query / prepared statement - bind the value "
        "through a placeholder (?, %s or :name) instead of building the SQL by "
        "hand. Complete and verify the fix in the training sandbox for this finding."
    )


_SECTION_BUILDERS = {
    "MANAGEMENT": _management_section,
    "HR_DATA_PROTECTION": _hr_section,
    "IT_GENERALIST": _it_section,
    "DEVELOPER": _developer_section,
}

_HEADERS = {
    "MANAGEMENT": "Management summary",
    "HR_DATA_PROTECTION": "HR & data-protection briefing",
    "IT_GENERALIST": "IT remediation summary",
    "DEVELOPER": "Developer remediation detail",
}


def build_report_text(findings, audience="MANAGEMENT"):
    """Return the report text for `findings`, tailored to `audience`.

    `audience` is one of AUDIENCES; anything else falls back to MANAGEMENT so
    older callers (and the default report view) keep working."""
    if audience not in _SECTION_BUILDERS:
        audience = "MANAGEMENT"

    confirmed, possible = _reportable(findings)
    reportable = confirmed + possible
    if not reportable:
        return f"{_HEADERS[audience]}\n\n{CLEAN_TEXT}"

    builder = _SECTION_BUILDERS[audience]
    sections = [builder(f, i + 1) for i, f in enumerate(reportable)]

    header = (
        f"{_HEADERS[audience]}\n"
        f"{len(confirmed)} confirmed and {len(possible)} possible finding(s) "
        "covered in this report:\n"
    )
    if possible:
        header += ("(Possible findings were flagged by one technique but not "
                   "corroborated - treat them as needing confirmation.)\n")
    return header + "\n" + "\n\n".join(sections)
