#!/usr/bin/env python3
"""PDF active-content test file generator.

Generates a minimal, valid PDF from scratch (raw PDF objects, no
libraries) that contains benign active-content test markers. The file
is used to test how upload filters, mail gateways, antivirus and DLP
products handle PDFs that carry:

1. An OpenAction JavaScript action that only shows a fixed test alert.
2. An embedded file attachment (a harmless .txt marker file).
3. Visible page text stating it is a security test file.

Everything in the generated PDF is a fixed, harmless marker. There is
no command execution, no network access and no obfuscation.

Zero dependencies: Python 3.9+ standard library only.
For authorised security testing only.
"""

from __future__ import annotations

import argparse
import sys

ALERT_MESSAGE = (
    "SECURITY TEST PDF - active content test file generated for "
    "authorised testing"
)
DEFAULT_EMBED_TEXT = (
    "SECURITY TEST PDF - embedded file attachment test marker. "
    "This is a harmless text file used for authorised upload filter, "
    "mail gateway, antivirus and DLP testing."
)
ATTACHMENT_NAME = "test_attachment.txt"

PAGE_LINES = [
    "SECURITY TEST FILE",
    "This PDF contains benign active-content test markers.",
    "It may open with a JavaScript alert and it carries a",
    "harmless text file attachment. Both are fixed test markers.",
    "For authorised security testing only.",
]


def _escape_pdf_string(text: str) -> str:
    """Escape a string for use inside PDF ( ) literal string syntax."""
    return (
        text.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def build_pdf(
    embed_text: str | None = None,
    include_js: bool = True,
    include_attachment: bool = True,
) -> bytes:
    """Build the test PDF and return it as bytes.

    Object numbers are assigned dynamically so optional objects (the
    JavaScript action and the embedded file) can be dropped cleanly.
    Cross-reference offsets are computed from the actual byte positions.
    """
    if embed_text is None:
        embed_text = DEFAULT_EMBED_TEXT

    objects: dict[int, bytes] = {}
    next_num = 1

    def alloc() -> int:
        nonlocal next_num
        num = next_num
        next_num += 1
        return num

    catalog_num = alloc()
    pages_num = alloc()
    page_num = alloc()
    content_num = alloc()
    font_num = alloc()

    js_num = alloc() if include_js else None
    ef_stream_num = alloc() if include_attachment else None
    filespec_num = alloc() if include_attachment else None
    names_num = alloc() if include_attachment else None

    # --- Page content stream: visible test notice text ---
    content_lines = ["BT", "/F1 24 Tf", "72 720 Td"]
    content_lines.append(f"({_escape_pdf_string(PAGE_LINES[0])}) Tj")
    content_lines.append("/F1 12 Tf")
    content_lines.append("0 -36 Td")
    for line in PAGE_LINES[1:]:
        content_lines.append(f"({_escape_pdf_string(line)}) Tj")
        content_lines.append("0 -18 Td")
    content_lines.append("ET")
    content_bytes = "\n".join(content_lines).encode("ascii")
    objects[content_num] = (
        f"<< /Length {len(content_bytes)} >>\nstream\n".encode("ascii")
        + content_bytes
        + b"\nendstream"
    )

    objects[font_num] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    objects[page_num] = (
        f"<< /Type /Page /Parent {pages_num} 0 R "
        f"/MediaBox [0 0 612 792] "
        f"/Contents {content_num} 0 R "
        f"/Resources << /Font << /F1 {font_num} 0 R >> >> >>"
    ).encode("ascii")

    objects[pages_num] = (
        f"<< /Type /Pages /Kids [{page_num} 0 R] /Count 1 >>"
    ).encode("ascii")

    # --- Optional JavaScript OpenAction (benign alert only) ---
    if include_js and js_num is not None:
        js_code = f'app.alert("{ALERT_MESSAGE}");'
        objects[js_num] = (
            f"<< /Type /Action /S /JavaScript "
            f"/JS ({_escape_pdf_string(js_code)}) >>"
        ).encode("ascii")

    # --- Optional embedded file attachment ---
    if include_attachment and ef_stream_num is not None and filespec_num is not None and names_num is not None:
        embed_bytes = embed_text.encode("utf-8")
        objects[ef_stream_num] = (
            f"<< /Type /EmbeddedFile /Subtype /text#2Fplain "
            f"/Params << /Size {len(embed_bytes)} >> "
            f"/Length {len(embed_bytes)} >>\nstream\n".encode("ascii")
            + embed_bytes
            + b"\nendstream"
        )
        objects[filespec_num] = (
            f"<< /Type /Filespec /F ({ATTACHMENT_NAME}) "
            f"/Desc (Benign security test attachment marker) "
            f"/AFRelationship /Data "
            f"/EF << /F {ef_stream_num} 0 R >> >>"
        ).encode("ascii")
        objects[names_num] = (
            f"<< /Names [({ATTACHMENT_NAME}) {filespec_num} 0 R] >>"
        ).encode("ascii")

    # --- Catalog, referencing the optional objects when present ---
    catalog_parts = [
        "<< /Type /Catalog",
        f"/Pages {pages_num} 0 R",
    ]
    if include_js and js_num is not None:
        catalog_parts.append(f"/OpenAction {js_num} 0 R")
    if include_attachment and names_num is not None:
        catalog_parts.append(f"/Names << /EmbeddedFiles {names_num} 0 R >>")
    catalog_parts.append(">>")
    objects[catalog_num] = " ".join(catalog_parts).encode("ascii")

    # --- Assemble the file, recording the offset of every object ---
    out = bytearray()
    out += b"%PDF-1.4\n"
    # Binary marker comment, standard practice so tools treat the
    # file as binary rather than text.
    out += b"%\xe2\xe3\xcf\xd3\n"

    offsets: dict[int, int] = {}
    max_num = max(objects)
    for num in range(1, max_num + 1):
        if num not in objects:
            continue
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode("ascii")
        out += objects[num]
        out += b"\nendobj\n"

    xref_pos = len(out)
    size = max_num + 1
    out += f"xref\n0 {size}\n".encode("ascii")
    out += b"0000000000 65535 f \n"
    for num in range(1, size):
        offset = offsets.get(num, 0)
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += (
        f"trailer\n<< /Size {size} /Root {catalog_num} 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode("ascii")
    return bytes(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a benign PDF with active-content test markers "
            "(a fixed JavaScript alert and a text attachment) for "
            "authorised upload filter, mail gateway, AV and DLP testing."
        )
    )
    parser.add_argument("-o", "--output", default="test.pdf",
                        help="Output PDF path (default: test.pdf)")
    parser.add_argument("--embed-text", default=None,
                        help="Text to put inside the embedded .txt attachment")
    parser.add_argument("--no-js", action="store_true",
                        help="Do not include the JavaScript OpenAction alert")
    parser.add_argument("--no-attachment", action="store_true",
                        help="Do not include the embedded file attachment")
    args = parser.parse_args(argv)

    data = build_pdf(
        embed_text=args.embed_text,
        include_js=not args.no_js,
        include_attachment=not args.no_attachment,
    )
    with open(args.output, "wb") as fh:
        fh.write(data)
    print(f"Wrote {args.output} ({len(data)} bytes)")
    print(f"  JavaScript OpenAction alert: {'no' if args.no_js else 'yes'}")
    print(f"  Embedded text attachment:    {'no' if args.no_attachment else 'yes'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
