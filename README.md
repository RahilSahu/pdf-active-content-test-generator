# PDF Active-Content Test Generator

A small, zero-dependency Python tool that builds a minimal, valid PDF
from scratch (raw PDF objects with correctly computed cross-reference
offsets, no PDF library) containing benign active-content test markers.

It exists for one job: checking how upload filters, mail gateways,
antivirus and DLP products handle a PDF that carries active content and
an embedded file. Security teams need a safe, repeatable test file for
that. This is that file.

## What the generated PDF contains

- An OpenAction JavaScript action that only calls app.alert with a
  fixed test message: "SECURITY TEST PDF - active content test file
  generated for authorised testing". Nothing else. No command
  execution, no network calls, no obfuscation.
- An embedded file attachment, a .txt file whose content is a fixed
  test marker string, attached through the standard EmbeddedFiles
  name tree.
- Visible page text stating clearly that it is a security test file.

## Usage

```bash
python3 pdf_test_gen.py -o test.pdf
python3 pdf_test_gen.py -o test.pdf --embed-text "my own marker text"
python3 pdf_test_gen.py -o test.pdf --no-js
python3 pdf_test_gen.py -o test.pdf --no-attachment
```

Options:

- `-o, --output`: output path, default `test.pdf`
- `--embed-text "..."`: replace the text inside the embedded .txt
  attachment with your own marker
- `--no-js`: generate the PDF without the JavaScript OpenAction
- `--no-attachment`: generate the PDF without the embedded file

Generating the variants separately is useful: it lets you tell whether
a filter is reacting to the JavaScript, to the attachment, or to both.

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests verify that the output starts with %PDF, contains the alert
and EmbeddedFiles markers, that the no-JavaScript option removes the
JavaScript object, and, most importantly, that every cross-reference
offset actually points at the object header it claims to point at.
That last check is what proves the hand-built PDF structure is sound.

## Responsible use

For authorised security testing only. Use the generated files to test
systems you own or are explicitly authorised to test, for example your
own upload form, mail gateway, antivirus or DLP policy. The markers
are benign by design, but a test file dropped into someone else's
system without permission is still a problem. Do not misuse it.

## License

MIT, see LICENSE.
