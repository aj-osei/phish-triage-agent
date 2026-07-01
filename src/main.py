from __future__ import annotations

import re
import sys
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import List


URL_PATTERN = re.compile(r"https?://[^\s<>()\[\]{}\"']+")


def resolve_eml_path() -> Path:
    """Return the .eml path from CLI arg or default samples folder."""
    if len(sys.argv) > 1:
        return Path(sys.argv[1]).expanduser().resolve()

    project_root = Path(__file__).resolve().parent.parent
    return project_root / "samples" / "test_email.eml"


def read_eml_bytes(eml_path: Path) -> bytes:
    """Read the email file as raw bytes for safe parsing."""
    return eml_path.read_bytes()


def parse_email(raw_email: bytes):
    """Parse the raw bytes into an EmailMessage object."""
    return BytesParser(policy=policy.default).parsebytes(raw_email)


def decode_header_value(value: str | None) -> str:
    """Decode encoded headers into readable text."""
    if not value:
        return "(not provided)"

    decoded_parts = []
    for part, encoding in decode_header(value):
        if isinstance(part, bytes):
            decoded_parts.append(part.decode(encoding or "utf-8", errors="replace"))
        else:
            decoded_parts.append(part)
    return "".join(decoded_parts).strip() or "(not provided)"


def extract_plain_text_body(message) -> str:
    """Collect plain text body content and ignore HTML/attachments."""
    text_chunks: List[str] = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = (part.get_content_disposition() or "").lower()

            # Skip attachments and non-plain-text parts.
            if content_disposition == "attachment":
                continue
            if content_type != "text/plain":
                continue

            payload = part.get_content()
            if isinstance(payload, str):
                text_chunks.append(payload)
    else:
        if message.get_content_type() == "text/plain":
            payload = message.get_content()
            if isinstance(payload, str):
                text_chunks.append(payload)

    return "\n".join(chunk.strip() for chunk in text_chunks if chunk.strip())


def make_body_preview(body_text: str, max_chars: int = 240) -> str:
    """Build a short one-line preview of the email body."""
    compact_text = " ".join(body_text.split())
    if not compact_text:
        return "(no plain-text body found)"

    if len(compact_text) <= max_chars:
        return compact_text
    return compact_text[:max_chars].rstrip() + "..."


def extract_urls(text: str) -> List[str]:
    """Find URLs in text while preserving first-seen order."""
    found = URL_PATTERN.findall(text)
    unique_urls = list(dict.fromkeys(found))
    return unique_urls


def print_summary(message) -> None:
    """Print key fields and safe content summary."""
    sender = parseaddr(decode_header_value(message.get("From")))[1] or "(not provided)"
    recipient = parseaddr(decode_header_value(message.get("To")))[1] or "(not provided)"
    subject = decode_header_value(message.get("Subject"))
    sent_date = decode_header_value(message.get("Date"))

    body_text = extract_plain_text_body(message)
    preview = make_body_preview(body_text)
    urls = extract_urls(body_text)

    print("=== Email Triage Summary ===")
    print(f"From: {sender}")
    print(f"To: {recipient}")
    print(f"Subject: {subject}")
    print(f"Date: {sent_date}")
    print(f"Body Preview: {preview}")

    print("URLs Found:")
    if urls:
        for url in urls:
            print(f"- {url}")
    else:
        print("- None")


def main() -> None:
    """Entry point for local .eml phishing triage parsing."""
    eml_path = resolve_eml_path()

    if not eml_path.exists():
        print(f"Error: file not found: {eml_path}")
        sys.exit(1)

    raw_email = read_eml_bytes(eml_path)
    message = parse_email(raw_email)
    print_summary(message)


if __name__ == "__main__":
    main()
