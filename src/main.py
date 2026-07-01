from __future__ import annotations

import re
import sys
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Dict, List


URL_PATTERN = re.compile(r"https?://[^\s<>()\[\]{}\"']+")
AUTH_RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)


def resolve_eml_path() -> Path:
    """Return the .eml path from CLI arg or default samples folder."""
    if len(sys.argv) > 1:
        return Path(sys.argv[1]).expanduser().resolve()

    project_root = Path(__file__).resolve().parent.parent
    return project_root / "samples" / "test_email.eml"


def read_eml_bytes(eml_path: Path) -> bytes:
    """Read the email file as raw bytes for safe parsing."""
    return eml_path.read_bytes()


def resolve_report_path() -> Path:
    """Return the default Markdown report path in the reports folder."""
    project_root = Path(__file__).resolve().parent.parent
    return project_root / "reports" / "test_email_report.md"


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


def get_header_or_not_found(message, header_name: str) -> str:
    """Return a decoded single header value or Not found."""
    header_value = message.get(header_name)
    if not header_value:
        return "Not found"
    return decode_header_value(header_value)


def get_all_headers_or_not_found(message, header_name: str) -> List[str]:
    """Return all decoded values for a repeating header, or Not found."""
    values = message.get_all(header_name, [])
    if not values:
        return ["Not found"]

    decoded_values = []
    for value in values:
        decoded = decode_header_value(value)
        decoded_values.append(decoded if decoded else "Not found")
    return decoded_values


def parse_authentication_results(auth_values: List[str]) -> Dict[str, str]:
    """Extract SPF, DKIM, and DMARC result tokens from Authentication-Results."""
    combined = " ".join(v for v in auth_values if v != "Not found")
    results = {"spf": "Not found", "dkim": "Not found", "dmarc": "Not found"}

    for mechanism, result in AUTH_RESULT_PATTERN.findall(combined):
        key = mechanism.lower()
        if key in results and results[key] == "Not found":
            results[key] = result.lower()

    return results


def normalize_header_whitespace(value: str) -> str:
    """Collapse repeated spaces to make long headers easier to read."""
    return " ".join(value.split())


def parse_received_header(received_header: str) -> Dict[str, object]:
    """Parse a Received header into analyst-friendly route fields."""
    cleaned = normalize_header_whitespace(received_header)

    from_match = re.search(r"\bfrom\s+(.+?)(?=\s+by\b|\s+with\b|\s+for\b|;|$)", cleaned, re.IGNORECASE)
    by_match = re.search(r"\bby\s+(.+?)(?=\s+with\b|\s+for\b|;|$)", cleaned, re.IGNORECASE)
    ip_match = re.search(r"\[([0-9a-fA-F:.]+)\]", cleaned)
    timestamp = cleaned.split(";", 1)[1].strip() if ";" in cleaned else "Not found"

    from_server = from_match.group(1).strip() if from_match else "Not found"
    by_server = by_match.group(1).strip() if by_match else "Not found"
    source_ip = ip_match.group(1).strip() if ip_match else "Not found"
    is_parsed = any(value != "Not found" for value in [from_server, by_server, source_ip, timestamp])

    return {
        "from_server": from_server,
        "source_ip": source_ip,
        "by_server": by_server,
        "timestamp": timestamp,
        "raw": cleaned,
        "parsed": is_parsed,
    }


def build_received_route_details(received_headers: List[str]) -> List[Dict[str, object]]:
    """Create parsed route details for every Received header."""
    if received_headers == ["Not found"]:
        return []

    parsed_routes = []
    for header in received_headers:
        parsed_routes.append(parse_received_header(header))
    return parsed_routes


def find_likely_originating_ip(received_routes: List[Dict[str, object]]) -> str:
    """Use the earliest observed Received hop with an IP as a possible origin."""
    for route in reversed(received_routes):
        source_ip = route.get("source_ip", "Not found")
        if source_ip != "Not found":
            return source_ip
    return "Not found"


def find_last_sending_relay_ip(received_routes: List[Dict[str, object]]) -> str:
    """Use the latest Received hop source IP as the last relay indicator."""
    for route in received_routes:
        source_ip = route.get("source_ip", "Not found")
        if source_ip != "Not found":
            return source_ip
    return "Not found"


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


def build_summary_data(message) -> Dict[str, object]:
    """Extract a simple summary dictionary from the parsed email."""
    sender = parseaddr(decode_header_value(message.get("From")))[1] or "(not provided)"
    recipient = parseaddr(decode_header_value(message.get("To")))[1] or "(not provided)"
    subject = decode_header_value(message.get("Subject"))
    sent_date = decode_header_value(message.get("Date"))

    body_text = extract_plain_text_body(message)
    preview = make_body_preview(body_text)
    urls = extract_urls(body_text)
    authentication_results = get_all_headers_or_not_found(message, "Authentication-Results")
    return_path = get_header_or_not_found(message, "Return-Path")
    reply_to = get_header_or_not_found(message, "Reply-To")
    received_headers = get_all_headers_or_not_found(message, "Received")
    received_routes = build_received_route_details(received_headers)
    likely_originating_ip = find_likely_originating_ip(received_routes)
    last_sending_relay_ip = find_last_sending_relay_ip(received_routes)
    auth_protocol_results = parse_authentication_results(authentication_results)

    return {
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "sent_date": sent_date,
        "body_preview": preview,
        "urls": urls,
        "authentication_results": authentication_results,
        "return_path": return_path,
        "reply_to": reply_to,
        "received_headers": received_headers,
        "received_routes": received_routes,
        "likely_originating_ip": likely_originating_ip,
        "last_sending_relay_ip": last_sending_relay_ip,
        "spf_result": auth_protocol_results["spf"],
        "dkim_result": auth_protocol_results["dkim"],
        "dmarc_result": auth_protocol_results["dmarc"],
    }


def print_summary(summary: Dict[str, object]) -> None:
    """Print key fields and safe content summary."""
    urls = summary["urls"]
    authentication_results = summary["authentication_results"]
    received_headers = summary["received_headers"]

    print("=== Email Triage Summary ===")
    print(f"From: {summary['sender']}")
    print(f"To: {summary['recipient']}")
    print(f"Subject: {summary['subject']}")
    print(f"Date: {summary['sent_date']}")
    print(f"Return-Path: {summary['return_path']}")
    print(f"Reply-To: {summary['reply_to']}")

    print("Authentication-Results:")
    for value in authentication_results:
        print(f"- {value}")

    print("Parsed Authentication Checks:")
    print(f"- SPF: {summary['spf_result']}")
    print(f"- DKIM: {summary['dkim_result']}")
    print(f"- DMARC: {summary['dmarc_result']}")

    print("Received Headers:")
    for value in received_headers:
        print(f"- {value}")

    print(f"Body Preview: {summary['body_preview']}")

    print("URLs Found:")
    if urls:
        for url in urls:
            print(f"- {url}")
    else:
        print("- None")


def build_markdown_report(summary: Dict[str, object]) -> str:
    """Build Markdown content for a local triage report."""
    urls = summary["urls"]
    authentication_results = summary["authentication_results"]
    received_headers = summary["received_headers"]
    received_routes = summary["received_routes"]
    lines = [
        "# Phishing Triage Report",
        "",
        "## Email Summary",
        "",
        f"- **From:** {summary['sender']}",
        f"- **To:** {summary['recipient']}",
        f"- **Subject:** {summary['subject']}",
        f"- **Date:** {summary['sent_date']}",
        f"- **Return-Path:** {summary['return_path']}",
        f"- **Reply-To:** {summary['reply_to']}",
        "",
        "## Body Preview",
        "",
        summary["body_preview"],
        "",
        "## URLs Found",
        "",
    ]

    if urls:
        for url in urls:
            lines.append(f"- {url}")
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Parsed Authentication Checks",
            "",
            f"- **SPF:** {summary['spf_result']}",
            f"- **DKIM:** {summary['dkim_result']}",
            f"- **DMARC:** {summary['dmarc_result']}",
            "",
            "## Authentication-Results Header",
            "",
        ]
    )

    for value in authentication_results:
        lines.append(f"- {normalize_header_whitespace(value)}")

    lines.extend(
        [
            "",
            "## Mail Route / Received Headers",
            "",
            "These findings are based on Received headers (mail transport path) and are not the same as the visible From sender.",
            "",
            f"- **Likely Originating IP:** {summary['likely_originating_ip']}",
            "  - Based on the earliest observed Received header that includes a source IP.",
            f"- **Last Sending Relay Before Recipient Mail Server:** {summary['last_sending_relay_ip']}",
            "  - Based on the latest Received header that includes a source IP.",
            "",
            "Parsed hops (earliest observed to latest):",
            "",
        ]
    )

    if received_routes:
        ordered_routes = list(reversed(received_routes))
        for index, route in enumerate(ordered_routes, start=1):
            lines.extend(
                [
                    f"### Hop {index}",
                    "",
                    f"- **From server:** {route['from_server']}",
                    f"- **Source IP:** {route['source_ip']}",
                    f"- **By server:** {route['by_server']}",
                    f"- **Timestamp:** {route['timestamp']}",
                ]
            )
            if not route["parsed"]:
                lines.append("- **Parse status:** Could not parse this header reliably.")
            lines.append(f"- **Raw header:** {route['raw']}")
            lines.append("")
    else:
        lines.append("- Not found")

    lines.extend(
        [
            "",
            "## Raw Received Headers",
            "",
        ]
    )

    for value in received_headers:
        lines.append(f"- {normalize_header_whitespace(value)}")

    return "\n".join(lines) + "\n"


def write_markdown_report(report_path: Path, report_content: str) -> None:
    """Write report content to reports/test_email_report.md."""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_content, encoding="utf-8")


def main() -> None:
    """Entry point for local .eml phishing triage parsing."""
    eml_path = resolve_eml_path()
    report_path = resolve_report_path()

    if not eml_path.exists():
        print(f"Error: file not found: {eml_path}")
        sys.exit(1)

    raw_email = read_eml_bytes(eml_path)
    message = parse_email(raw_email)
    summary = build_summary_data(message)

    print_summary(summary)

    report_content = build_markdown_report(summary)
    write_markdown_report(report_path, report_content)
    print(f"\nMarkdown report saved to: {report_path}")


if __name__ == "__main__":
    main()
