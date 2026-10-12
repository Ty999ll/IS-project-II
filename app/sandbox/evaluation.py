"""
Checks if the developer's fix "looks" like a parameterized query.

Limitations: this is just regex matching on the text, not a real static
analyser or AST parser. It can't run the code or properly verify it, that's
why there's the live re-test in sandbox/routes.py. This check only decides if
it's worth doing the re-test. It looks for string concatenation (bad) and
a placeholder like ?, %s or :name (good). Someone could easily trick it if
they wanted to. Parsing the code properly would be better, planned for later.
"""
import re

CONCAT_PATTERNS = [
    r"'\s*\+", r"\+\s*'",           # '...' + var  or  var + '...'
    r'"\s*\+', r'\+\s*"',           # same thing with double quotes
    r"%s\s*%\s*",                    # old style % formatting to build the SQL
    r"f['\"].*\{.*\}.*['\"]",       # f-string putting the value straight in the query
    r"\.format\(",                   # using .format() to build the query
]

PLACEHOLDER_PATTERNS = [
    r"\?",            # sqlite3 placeholder
    r"%s",            # psycopg2 / MySQLdb placeholder (the concat check above catches the bad use of %s)
    r":\w+",          # named placeholder like :id
    r"\bexecute\([^,]+,\s*\(",   # cursor.execute(query, (params,))
]


def evaluate_submission(code_text):
    """Returns a tuple (passed, feedback) where passed is True/False."""
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
