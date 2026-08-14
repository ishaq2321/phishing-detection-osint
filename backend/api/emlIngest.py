"""
EML Ingestion Module (Tier 4 E)
===============================

Parses raw RFC 822 / MIME ``.eml`` bytes into the fields the existing
email-analysis pipeline consumes (subject, sender, body) plus a small
metadata summary (recipients, attachment filenames, size) so operators
forwarding a real phishing email get back both the verdict AND what
was parsed from the file.

Why the stdlib ``email`` package?

* ``email.parser.BytesParser`` is the reference RFC 822 / MIME
  implementation shipped with CPython -- no new dependency.
* It is deliberately *lenient*: malformed messages degrade to
  partial fields instead of crashing, which matches the "graceful
  degradation" philosophy of the rest of the API.

Behaviour contract
------------------

``parseEmails(raw)`` never raises for malformed input.  If the bytes
do not contain a usable text body, ``body`` is ``""`` and the caller
(the route) decides how to react (HTTP 422).

Body extraction order (mirrors what an investigator sees):

1. First ``text/plain`` part (walking the MIME tree, depth-first).
2. Else the first ``text/html`` part, with tags stripped and
   entities decoded into plain text.
3. Else all text parts joined (rare multipart layouts).

Header decoding (RFC 2047 encoded-words, e.g. ``=?utf-8?Q?...?=``)
is handled by ``email.header``; ``email.utils.parseaddr`` splits
``"Name <addr@example.com>"`` into ``(name, address)``.
"""

from __future__ import annotations

import html as htmlLib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from typing import Optional

# The size cap lives in ``config.Settings.emlMaxBytes`` (env
# ``EML_MAX_BYTES``, default 1 MB) and is enforced by the route as
# HTTP 413 -- see ``backend/api/router.py::ingestEmail``.

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t\r\f\v]+")


@dataclass
class ParsedEmail:
    """Extracted fields from a raw ``.eml`` payload.

    Attributes:
        subject: Decoded subject line (may be empty).
        senderName: Display name from the From header (may be empty).
        senderAddress: Email address from the From header (may be empty).
        recipients: List of addresses from To / Cc (may be empty).
        body: Plain-text body extracted from the MIME tree (may be empty).
        hasAttachments: True when the message carries non-text parts.
        attachmentNames: Filenames of attachments (may be empty).
        sizeBytes: Raw payload size in bytes.
    """

    subject: str = ""
    senderName: str = ""
    senderAddress: str = ""
    recipients: list[str] = field(default_factory=list)
    body: str = ""
    hasAttachments: bool = False
    attachmentNames: list[str] = field(default_factory=list)
    sizeBytes: int = 0


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _decodeHeader(value: Optional[str]) -> str:
    """Decode an RFC 2047 encoded header into plain Unicode text."""
    if not value:
        return ""
    try:
        from email.header import decode_header

        pieces: list[str] = []
        for raw, charset in decode_header(value):
            if isinstance(raw, bytes):
                pieces.append(raw.decode(charset or "utf-8", errors="replace"))
            else:
                pieces.append(raw)
        return "".join(pieces).strip()
    except Exception:
        # Never let a malformed header take down the whole ingest.
        return value.strip()


def _splitAddr(value: Optional[str]) -> tuple[str, str]:
    """Split ``"Name <addr>"`` into ``(name, address)``, both decoded."""
    from email.utils import parseaddr

    name, address = parseaddr(value or "")
    return _decodeHeader(name), (address or "").strip().lower()


def _normaliseBody(text: str) -> str:
    """Collapse runs of whitespace / blank lines for analyser hygiene."""
    lines = [_WS_RE.sub(" ", line).rstrip() for line in text.splitlines()]
    return "\n".join(lines).strip()


def _extractBodyFromPart(part) -> str:
    """Extract and decode the payload of a single (non-multipart) part."""
    charset = part.get_content_charset() or "utf-8"
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""


def _stripHtml(raw: str) -> str:
    """Turn an HTML body into readable plain text.

    Removes tags, decodes entities, and keeps paragraph breaks.
    """
    text = re.sub(r"(?i)<br\s*/?>", "\n", raw)
    text = re.sub(r"(?i)</(p|div|tr|li|h[1-6])>", "\n", text)
    text = _TAG_RE.sub("", text)
    return htmlLib.unescape(text)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parseEmails(raw: bytes) -> ParsedEmail:
    """Parse raw RFC 822 / MIME bytes into a :class:`ParsedEmail`.

    Never raises on malformed input -- the stdlib parser is lenient
    and every extraction step is guarded.  An unusable payload shows
    up as an empty ``body`` / ``subject``, which the caller can turn
    into a 422.
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw or b"")

    parsed = ParsedEmail(sizeBytes=len(raw or b""))
    parsed.subject = _decodeHeader(msg.get("Subject"))
    parsed.senderName, parsed.senderAddress = _splitAddr(msg.get("From"))

    recipients: list[str] = []
    for headerName in ("To", "Cc"):
        for value in msg.get_all(headerName, []):
            for rawAddr in re.split(r"[,;]", value):
                _, addr = _splitAddr(rawAddr)
                if addr:
                    recipients.append(addr)
    parsed.recipients = recipients

    # -- Body + attachment extraction -----------------------------------
    textParts: list[str] = []
    htmlParts: list[str] = []
    attachments: list[str] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        contentType = (part.get_content_type() or "").lower()
        disposition = (part.get("Content-Disposition") or "").lower()

        filename = part.get_filename()
        if filename:
            attachments.append(_decodeHeader(filename))

        isAttachment = "attachment" in disposition or (
            filename is not None and contentType not in ("text/plain", "text/html")
        )
        if isAttachment:
            continue

        if contentType == "text/plain":
            textParts.append(_extractBodyFromPart(part))
        elif contentType == "text/html":
            htmlParts.append(_stripHtml(_extractBodyFromPart(part)))

    if textParts:
        parsed.body = _normaliseBody("\n".join(textParts))
    elif htmlParts:
        parsed.body = _normaliseBody("\n".join(htmlParts))

    parsed.hasAttachments = bool(attachments)
    parsed.attachmentNames = attachments
    return parsed


def buildEmailContent(parsed: ParsedEmail) -> str:
    """Assemble the orchestrator input string from a parsed email.

    Mirrors the ``/api/analyze/email`` route's body assembly so the
    NLP analyser sees the same ``Subject:`` / ``From:`` header lines
    it does for the JSON endpoint -- identical scoring semantics.
    """
    content = parsed.body
    if parsed.subject:
        content = f"Subject: {parsed.subject}\n\n{content}"
    if parsed.senderAddress:
        senderLine = parsed.senderAddress
        if parsed.senderName and parsed.senderName.lower() != senderLine:
            senderLine = f"{parsed.senderName} <{parsed.senderAddress}>"
        content = f"From: {senderLine}\n{content}"
    return content
