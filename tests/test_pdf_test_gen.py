import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pdf_test_gen import ALERT_MESSAGE, build_pdf


def parse_xref_offsets(data: bytes) -> dict:
    """Parse the xref table and return {object_number: offset}."""
    startxref_match = re.search(rb"startxref\s*(\d+)\s*%%EOF", data)
    assert startxref_match, "startxref not found"
    xref_pos = int(startxref_match.group(1))
    assert data[xref_pos:xref_pos + 4] == b"xref", "startxref does not point at xref"

    lines = data[xref_pos:].split(b"\n")
    # lines[0] is "xref", lines[1] is "0 N", entries follow.
    first, count = (int(part) for part in lines[1].split())
    assert first == 0
    offsets = {}
    for i in range(count):
        entry = lines[2 + i].decode("ascii")
        offset = int(entry[0:10])
        kind = entry[17]
        if kind == "n":
            offsets[i] = offset
    return offsets


class BuildPdfTests(unittest.TestCase):
    def setUp(self):
        self.data = build_pdf()

    def test_starts_with_pdf_header(self):
        self.assertTrue(self.data.startswith(b"%PDF"))

    def test_ends_with_eof(self):
        self.assertTrue(self.data.rstrip().endswith(b"%%EOF"))

    def test_contains_alert_message(self):
        self.assertIn(ALERT_MESSAGE.encode("ascii"), self.data)
        self.assertIn(b"app.alert", self.data)
        self.assertIn(b"/JavaScript", self.data)

    def test_contains_embedded_files_marker(self):
        self.assertIn(b"/EmbeddedFiles", self.data)
        self.assertIn(b"/Filespec", self.data)
        self.assertIn(b"test_attachment.txt", self.data)

    def test_contains_visible_test_text(self):
        self.assertIn(b"SECURITY TEST FILE", self.data)

    def test_custom_embed_text_is_used(self):
        data = build_pdf(embed_text="CUSTOM MARKER TEXT 12345")
        self.assertIn(b"CUSTOM MARKER TEXT 12345", data)

    def test_xref_offsets_point_at_objects(self):
        offsets = parse_xref_offsets(self.data)
        self.assertGreater(len(offsets), 4)
        for num, offset in offsets.items():
            expected = f"{num} 0 obj".encode("ascii")
            self.assertEqual(
                self.data[offset:offset + len(expected)],
                expected,
                f"xref offset for object {num} does not point at its header",
            )

    def test_no_js_removes_javascript_object(self):
        data = build_pdf(include_js=False)
        self.assertNotIn(b"/JavaScript", data)
        self.assertNotIn(b"app.alert", data)
        self.assertNotIn(b"/OpenAction", data)
        # The attachment should still be there.
        self.assertIn(b"/EmbeddedFiles", data)

    def test_no_attachment_removes_embedded_files(self):
        data = build_pdf(include_attachment=False)
        self.assertNotIn(b"/EmbeddedFiles", data)
        self.assertNotIn(b"/Filespec", data)
        # The JavaScript marker should still be there.
        self.assertIn(b"/JavaScript", data)

    def test_xref_still_valid_without_optional_objects(self):
        for kwargs in (
            {"include_js": False},
            {"include_attachment": False},
            {"include_js": False, "include_attachment": False},
        ):
            data = build_pdf(**kwargs)
            offsets = parse_xref_offsets(data)
            for num, offset in offsets.items():
                expected = f"{num} 0 obj".encode("ascii")
                self.assertEqual(data[offset:offset + len(expected)], expected)


if __name__ == "__main__":
    unittest.main()
