"""
Turns a plain-text report into a PDF file (roadmap item 11), with no extra
dependency: it writes the PDF objects directly using the standard Helvetica
font that every PDF reader has built in.

Limitations: text only (no tables or images), A4 pages, and line wrapping is
by character count rather than exact glyph widths, so a line of mostly capitals
can run slightly wider than others. Characters outside Windows-1252 (the
built-in fonts' encoding) are replaced with '?'.
"""
import textwrap

PAGE_W, PAGE_H = 595, 842          # A4 in points
MARGIN = 50
FONT_SIZE = 10
LINE_H = 14
WRAP_CHARS = 92                    # fits (PAGE_W - 2*MARGIN) at 10pt Helvetica
LINES_PER_PAGE = (PAGE_H - 2 * MARGIN - 20) // LINE_H


def _escape(text):
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(text):
    """Wrap each line, keeping its leading indent on the continuation lines."""
    lines = []
    for raw in text.splitlines():
        if not raw.strip():
            lines.append("")
            continue
        indent = " " * (len(raw) - len(raw.lstrip()))
        lines.extend(textwrap.wrap(raw.strip(), width=WRAP_CHARS - len(indent),
                                   initial_indent=indent, subsequent_indent=indent,
                                   break_long_words=True) or [""])
    return lines


def _page_stream(lines, page_no, page_count):
    """Content stream for one page: (font, text) lines top-down plus a footer."""
    out = ["BT", f"{LINE_H} TL", f"{MARGIN} {PAGE_H - MARGIN} Td"]
    for font, text in lines:
        out.append(f"/{font} {FONT_SIZE + (4 if font == 'F2' else 0)} Tf")
        out.append(f"({_escape(text)}) Tj T*")
    out.append("ET")
    out.append(f"BT /F1 8 Tf {MARGIN} {MARGIN - 20} Td (Page {page_no} of {page_count}) Tj ET")
    return "\n".join(out).encode("cp1252", errors="replace")


def build_pdf(title, meta_lines, body):
    """Return PDF bytes: a bold `title`, then `meta_lines`, then the wrapped `body`."""
    lines = [("F2", title), ("F1", "")]
    lines += [("F1", m) for l in meta_lines for m in _wrap(l)]
    lines.append(("F1", ""))
    lines += [("F1", l) for l in _wrap(body)]

    pages = [lines[i:i + LINES_PER_PAGE] for i in range(0, len(lines), LINES_PER_PAGE)] or [[]]

    # object numbers: 1 catalog, 2 page tree, 3/4 fonts, then (page, content) pairs
    objects = {
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
    }
    kids = []
    for n, page_lines in enumerate(pages):
        page_obj, content_obj = 5 + 2 * n, 6 + 2 * n
        kids.append(f"{page_obj} 0 R")
        stream = _page_stream(page_lines, n + 1, len(pages))
        objects[content_obj] = (f"<< /Length {len(stream)} >>\nstream\n".encode()
                                + stream + b"\nendstream")
        objects[page_obj] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_obj} 0 R >>"
        ).encode()
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(pages)} >>".encode()

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(pdf)
        pdf += f"{num} 0 obj\n".encode() + objects[num] + b"\nendobj\n"
    xref_at = len(pdf)
    count = max(objects) + 1
    pdf += f"xref\n0 {count}\n0000000000 65535 f \n".encode()
    for num in range(1, count):
        pdf += f"{offsets[num]:010d} 00000 n \n".encode()
    pdf += f"trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode()
    return bytes(pdf)
