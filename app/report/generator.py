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

# plain-language explanation of each detection method, for non-specialist readers
PLAIN_METHOD = {
    "PASSIVE_ERROR_PATTERN": (
        "the site returned a database error message when the scanner entered unexpected "
        "characters, which is a clear sign the input reaches the database without being "
        "handled safely"),
    "ACTIVE_TIME_BASED": (
        "the site took noticeably longer to respond when the scanner sent input designed to "
        "make the database pause, which shows the input is being run as part of a database "
        "command"),
    "BOOLEAN_BLIND": (
        "the site's response changed depending on whether a true or a false test condition "
        "was slipped into the input, which shows the input is being used inside a database "
        "query even though no error message is shown"),
}

# plain-language explanation of each remediation status
STATUS_EXPLAIN = {
    "UNRESOLVED": "not yet fixed",
    "FIX_SUBMITTED": "a developer has submitted a fix that is waiting to be re-tested",
    "STILL_VULNERABLE": "a fix was attempted but the field is still vulnerable and needs another look",
    "VERIFIED_RESOLVED": "fixed and confirmed safe by re-testing the live site",
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
    method_plain = PLAIN_METHOD.get(f.detection_method, "the scanner's automated checks flagged this input")
    status = f.remediation_status or "UNRESOLVED"
    status_plain = STATUS_EXPLAIN.get(status, status.replace("_", " ").lower())
    kind = ("confirmed vulnerable" if f.finding_classification == "CONFIRMED_VULNERABLE"
            else "possibly vulnerable (still to be confirmed)")
    return (
        f"{i}. Input field '{f.parameter_name}' - {_severity(f)} risk ({kind}).\n\n"
        "   What this means in practice: this input on the scanned page can be used to "
        "interfere with the database behind the site. If it is left unfixed, someone could "
        "use it to view or change member records they should not be able to reach - the kind "
        "of personal and financial data the institution is responsible for protecting.\n\n"
        f"   How the scanner found it: {method_plain} (technical name: {method_label}).\n\n"
        f"   Where it stands now: {_status_label(f)} - {status_plain}.\n\n"
        "   What you should do next:\n"
        "     1. Assign this finding to a developer. The fix is to change the affected query "
        "so the input is passed in safely as a value, rather than being joined straight into "
        "the database command. Your developer will know this as using a 'parameterised query' "
        "or 'prepared statement'; they don't need to rewrite the whole page, just that query.\n"
        "     2. The developer can work through and submit the fix in this system's training "
        "sandbox. When they do, the system automatically re-tests the exact same field "
        "against the live site, so you get independent confirmation rather than taking the "
        "fix on trust.\n"
        "     3. Only treat the finding as resolved once that re-test comes back clean. If it "
        "still shows as vulnerable, send it back to the developer for another attempt - the "
        "system will flag it for re-review rather than letting it be closed.\n"
        "     4. Because member personal data is at risk, treat this as time-sensitive: see "
        "the data-protection note in the briefing above about the 72-hour reporting window."
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

# a plain-language preamble shown once, before the findings, for audiences that
# benefit from context. The IT generalist isn't a security specialist, so this
# explains what SQL injection is and states the data-protection obligation once,
# so the per-finding sections can stay focused on what to do.
_INTROS = {
    "IT_GENERALIST": (
        "About this report: it lists the input fields on the scanned page that are "
        "vulnerable, or possibly vulnerable, to SQL injection, and what to do about each "
        "one. SQL injection is where text entered into a web form or a web address is "
        "mistakenly treated by the site as commands for its database, instead of as plain "
        "data. When that happens, an attacker can read, change or delete information in the "
        "database - including members' personal and financial records - without permission. "
        "The fix is well understood and is usually a small change per affected query; the "
        "sections below explain each finding in plain terms and walk through getting it "
        "fixed and confirmed resolved.\n\n"
        + DPA_OBLIGATION
    ),
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

    body = header + "\n"
    if audience in _INTROS:
        body += _INTROS[audience] + "\n\n"
    return body + "\n\n".join(sections)
