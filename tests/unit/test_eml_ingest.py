"""
Unit tests for ``backend/api/emlIngest.py`` (Tier 4 E).

Covers the RFC 822 / MIME parser contract:

* simple text message -> subject / sender / body extracted
* multipart/alternative -> text/plain preferred over text/html
* HTML-only message -> tags stripped, entities decoded
* RFC 2047 encoded-words in Subject / From headers
* quoted-printable and base64 transfer encodings
* attachment detection (Content-Disposition / filename)
* malformed / empty bytes degrade gracefully (no raise)
* ``buildEmailContent`` mirrors the /api/analyze/email assembly
"""

from __future__ import annotations

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

import pytest

from backend.api.emlIngest import (
    buildEmailContent,
    parseEmails,
)


# ---------------------------------------------------------------------------
# Fixtures: realistic .eml payload builders
# ---------------------------------------------------------------------------

def simpleEml(subject: str = "Security Alert") -> bytes:
    msg = MIMEText("Urgent! Your account will be suspended. Verify now.", "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = "security@paypa1-support.com"
    msg["To"] = "victim@example.com"
    return msg.as_bytes()


def multipartEml() -> bytes:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Invoice #1042"
    msg["From"] = "billing@example.com"
    msg["To"] = "user@example.org"
    msg.attach(MIMEText("Please find your invoice attached.", "plain", "utf-8"))
    msg.attach(MIMEText("<html><body><p>Please find your <b>invoice</b> attached.</p></body></html>", "html", "utf-8"))
    return msg.as_bytes()


def emlWithAttachment() -> bytes:
    msg = MIMEMultipart()
    msg["Subject"] = "Documents"
    msg["From"] = "sender@example.com"
    msg.attach(MIMEText("See the attached file.", "plain", "utf-8"))
    attachment = MIMEApplication(b"PDF content", _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename="invoice.pdf")
    msg.attach(attachment)
    return msg.as_bytes()


# ---------------------------------------------------------------------------
# Basic field extraction
# ---------------------------------------------------------------------------

def test_parse_simple_message():
    parsed = parseEmails(simpleEml())
    assert parsed.subject == "Security Alert"
    assert parsed.senderAddress == "security@paypa1-support.com"
    assert parsed.senderName == ""
    assert parsed.recipients == ["victim@example.com"]
    assert "Urgent!" in parsed.body
    assert parsed.hasAttachments is False
    assert parsed.sizeBytes > 0


def test_parse_multipart_prefers_plain_text():
    parsed = parseEmails(multipartEml())
    assert parsed.body == "Please find your invoice attached."
    assert "<b>" not in parsed.body


def test_parse_html_only_message():
    msg = MIMEText("<html><body><p>Click <a href='https://evil.example'>here</a> now.</p></body></html>", "html", "utf-8")
    msg["Subject"] = "HTML only"
    parsed = parseEmails(msg.as_bytes())
    assert "Click here now." in parsed.body
    assert "<a" not in parsed.body


def test_parse_attachment_detection():
    parsed = parseEmails(emlWithAttachment())
    assert parsed.hasAttachments is True
    assert parsed.attachmentNames == ["invoice.pdf"]
    # Attachment content must NOT leak into the analysed body.
    assert "PDF content" not in parsed.body


def test_parse_encoded_words_subject():
    msg = MIMEText("Body text", "plain", "utf-8")
    msg["Subject"] = "=?utf-8?Q?Achtung=21_Ihre_Rechnung?="
    msg["From"] = "noreply@example.com"
    parsed = parseEmails(msg.as_bytes())
    assert parsed.subject == "Achtung! Ihre Rechnung"


def test_parse_display_name_from_header():
    msg = MIMEText("Body", "plain", "utf-8")
    msg["From"] = formataddr(("PayPal Security", "security@paypa1-support.com"))
    parsed = parseEmails(msg.as_bytes())
    assert parsed.senderName == "PayPal Security"
    assert parsed.senderAddress == "security@paypa1-support.com"


def test_parse_quoted_printable_body():
    # Build the raw message by hand so the body really is QP-encoded
    # (MIMEText picks base64 for utf-8 payloads, which would make this
    # test silently exercise the wrong code path).
    import quopri

    body = "Caf\u00e9 \u00fcberall \u2014 check now"
    raw = (
        b"From: a@b.c\r\nSubject: QP\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        + quopri.encodestring(body.encode("utf-8"))
    )
    assert b"=C3" in raw  # confirm it is actually quoted-printable
    parsed = parseEmails(raw)
    assert "Café" in parsed.body


def test_parse_base64_body():
    import base64

    raw = (
        b"From: a@b.c\r\nSubject: Base64\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode("Base64 decoded body".encode("utf-8"))
    )
    parsed = parseEmails(raw)
    assert parsed.body == "Base64 decoded body"


def test_parse_missing_optional_headers():
    msg = MIMEText("Just a body with no headers at all beyond content-type", "plain", "utf-8")
    parsed = parseEmails(msg.as_bytes())
    assert parsed.subject == ""
    assert parsed.senderAddress == ""
    assert parsed.recipients == []
    assert "no headers" in parsed.body


# ---------------------------------------------------------------------------
# Degenerate input -- must degrade, never raise
# ---------------------------------------------------------------------------

def test_parse_empty_bytes():
    parsed = parseEmails(b"")
    assert parsed.body == ""
    assert parsed.subject == ""
    assert parsed.sizeBytes == 0


def test_parse_garbage_bytes():
    parsed = parseEmails(b"\x00\x01\x02not-an-email-at-all\xff\xfe")
    # Lenient parser: no crash; body just ends up empty.
    assert isinstance(parsed.body, str)


def test_parse_crlf_lf_variants():
    lfOnly = simpleEml().replace(b"\r\n", b"\n")
    parsed = parseEmails(lfOnly)
    assert parsed.subject == "Security Alert"


# ---------------------------------------------------------------------------
# buildEmailContent -- mirrors /api/analyze/email assembly
# ---------------------------------------------------------------------------

def test_buildContent_includes_subject_and_sender():
    parsed = parseEmails(simpleEml())
    content = buildEmailContent(parsed)
    # Assembly order mirrors /api/analyze/email: subject is wrapped
    # around the body first, then the From line is prepended.
    assert content.startswith("From: security@paypa1-support.com")
    assert "Subject: Security Alert" in content
    assert "Urgent!" in content


def test_buildContent_display_name_preferred():
    msg = MIMEText("Body", "plain", "utf-8")
    msg["Subject"] = "Hi"
    msg["From"] = formataddr(("PayPal Security", "security@paypa1-support.com"))
    parsed = parseEmails(msg.as_bytes())
    content = buildEmailContent(parsed)
    assert "From: PayPal Security <security@paypa1-support.com>" in content


def test_buildContent_without_subject():
    msg = MIMEText("Only a body here", "plain", "utf-8")
    msg["From"] = "a@b.c"
    parsed = parseEmails(msg.as_bytes())
    content = buildEmailContent(parsed)
    assert content.startswith("From: a@b.c")
