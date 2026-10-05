"""
Heuristic check on whether a developer's submitted fix "looks" parameterized.

Honesty note: this is a naive text heuristic, not a real static analyzer or
AST parser. It cannot execute or truly verify the submitted code — that's
what the live re-test step (verification.py) is for. This function only
gates whether it's worth spending a live request on: it looks for the
*absence* of raw string-concatenation patterns around the parameter and
the *presence* of a placeholder/binding style. A determined developer could
fool this heuristic; a real implementation would parse the code properly.
That's a documented "next slice" improvement, not a hidden gap.
"""
import re

CONCAT_PATTERNS = [
    r"'\s*\+", r"\+\s*'",           # '...' + var  /  var + '...'
    r'"\s*\+', r'\+\s*"',           # "..." + var
    r"%s\s*%\s*",                    # old % string formatting directly building SQL
    r"f['\"].*\{.*\}.*['\"]",       # f-string interpolation directly in a query literal
    r"\.format\(",                   # .format( ... ) building a query string
]

PLACEHOLDER_PATTERNS = [
    r"\?",            # sqlite3 / generic positional placeholder
    r"%s",            # psycopg2 / MySQLdb style (only counts if not caught by CONCAT check above)
    r":\w+",          # named binding, e.g. :id
    r"\bexecute\([^,]+,\s*\(",   # cursor.execute(query, (params,)) pattern
]


def evaluate_submission(code_text):
    """Returns (passed: bool, feedback: str)."""
    if not code_text or not code_text.strip():
        return False, "Submit a parameterized version of the query before checking."

    has_concat = any(re.search(p, code_text) for p in CONCAT_PATTERNS)
    has_placeholder = any(re.search(p, code_text) for p in PLACEHOLDER_PATTERNS)

    if has_concat and not has_placeholder:
        return False, ("This still looks like the parameter is being concatenated directly "
                        "into the query string. Use a placeholder (?, %s, or :name) and pass "
                        "the value separately instead of building the SQL string by hand.")

    if not has_placeholder:
        return False, ("No parameter placeholder detected (?, %s, or :name). Rewrite the query "
                        "to bind the value through the database driver's parameter mechanism.")

    return True, "Looks parameterized — proceeding to re-test against the live target."
