from __future__ import annotations

import re
import sys
import hashlib
import time
import ipaddress
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Dict, List
from urllib.parse import parse_qs, unquote, urlparse


URL_PATTERN = re.compile(r"https?://[^\s<>()\[\]{}\"']+")
AUTH_RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)
WATCH_POLL_SECONDS = 3
FILE_STABLE_WAIT_SECONDS = 2


def resolve_default_eml_path() -> Path:
    """Return the default .eml path in the samples folder."""
    project_root = Path(__file__).resolve().parent.parent
    return project_root / "samples" / "test_email.eml"


def resolve_eml_path(eml_path_arg: str | None) -> Path:
    """Return an .eml path from CLI input or use the default sample."""
    if eml_path_arg:
        return Path(eml_path_arg).expanduser().resolve()
    return resolve_default_eml_path()


def parse_cli_args() -> Dict[str, object]:
    """Parse command-line arguments for single-file or watch mode."""
    args = sys.argv[1:]

    if not args:
        return {"mode": "single", "eml_path": resolve_default_eml_path()}

    if args[0] == "--watch":
        if len(args) != 2:
            raise ValueError("Usage: python src/main.py --watch <watch_folder>")
        watch_folder = Path(args[1]).expanduser().resolve()
        return {"mode": "watch", "watch_folder": watch_folder}

    if len(args) != 1:
        raise ValueError("Usage: python src/main.py [path/to/file.eml]")

    return {"mode": "single", "eml_path": resolve_eml_path(args[0])}


def read_eml_bytes(eml_path: Path) -> bytes:
    """Read the email file as raw bytes for safe parsing."""
    return eml_path.read_bytes()


def resolve_report_path(eml_path: Path) -> Path:
    """Return a report path in reports/ based on the input .eml filename."""
    project_root = Path(__file__).resolve().parent.parent
    report_filename = f"{eml_path.stem}_report.md"
    return project_root / "reports" / report_filename


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


def format_address_line(header_value: str | None) -> str:
    """Format one email address header as Name <email> or email only."""
    if not header_value:
        return "Not found"

    decoded_value = decode_header_value(header_value)
    if decoded_value == "(not provided)":
        return "Not found"

    display_name, email_address = parseaddr(decoded_value)
    clean_name = " ".join(display_name.split()).strip('"')

    if email_address:
        if clean_name:
            return f"{clean_name} <{email_address}>"
        return email_address

    # Fall back to the decoded value if it is present but non-standard.
    return decoded_value.strip() or "Not found"


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
    """Use the earliest observed Received hop with a usable public IP."""
    for route in reversed(received_routes):
        source_ip = route.get("source_ip", "Not found")
        if source_ip != "Not found" and is_usable_public_ip(source_ip):
            return source_ip
    return "Not found"


def is_usable_public_ip(source_ip: str) -> bool:
    """Return True only for public, externally routable IP addresses."""
    try:
        ip_obj = ipaddress.ip_address(source_ip)
    except ValueError:
        return False

    if ip_obj.is_private:
        return False
    if ip_obj.is_loopback:
        return False
    if ip_obj.is_link_local:
        return False
    if ip_obj.is_multicast:
        return False
    if ip_obj.is_reserved:
        return False
    if ip_obj.is_unspecified:
        return False
    return True


def get_likely_originating_ip_note(likely_originating_ip: str) -> str:
    """Return an explanation of likely-originating-IP selection."""
    if likely_originating_ip == "Not found":
        return "No public external source IP was found in Received headers."
    return "Based on the earliest observed Received header with a usable public source IP."


def find_last_sending_relay_ip(received_routes: List[Dict[str, object]]) -> str:
    """Use the latest Received hop with a usable public IP as last relay."""
    for route in received_routes:
        source_ip = route.get("source_ip", "Not found")
        if source_ip != "Not found" and is_usable_public_ip(source_ip):
            return source_ip
    return "Not found"


def get_last_sending_relay_ip_note(last_sending_relay_ip: str) -> str:
    """Return an explanation of last-relay-IP selection."""
    if last_sending_relay_ip == "Not found":
        return "No public external relay IP was found in Received headers."
    return "Based on the latest Received header with a usable public source IP."


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


def remove_likely_signature_text(body_text: str) -> str:
    """Trim common signature lines to keep preview text readable."""
    lines = [line.strip() for line in body_text.splitlines() if line.strip()]
    preview_lines: List[str] = []

    for line in lines:
        lower_line = line.lower()

        if line == "--":
            break
        if lower_line.startswith("sent from"):
            break

        looks_like_signature_line = " | " in line and (
            "university" in lower_line
            or "college" in lower_line
            or "student" in lower_line
            or "mailto:" in lower_line
            or "p:" in lower_line
        )
        if looks_like_signature_line and preview_lines:
            break

        preview_lines.append(line)

    if not preview_lines:
        return body_text
    return "\n".join(preview_lines)


def make_body_preview(body_text: str, max_chars: int = 300) -> str:
    """Build a short one-line preview of the email body."""
    cleaned_text = remove_likely_signature_text(body_text)
    compact_text = " ".join(cleaned_text.split())
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


def is_microsoft_safe_link(url: str) -> bool:
    """Return True when a URL points to Microsoft Safe Links."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    hostname = (parsed.hostname or "").lower()
    return hostname.endswith("safelinks.protection.outlook.com")


def decode_safe_link_url(url: str) -> str | None:
    """Extract and decode the original destination from a Safe Link URL."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None

    hostname = (parsed.hostname or "").lower()
    if not hostname.endswith("safelinks.protection.outlook.com"):
        return None

    query_params = parse_qs(parsed.query)
    encoded_destinations = query_params.get("url", [])
    if not encoded_destinations:
        return None

    original_destination = encoded_destinations[0]
    return unquote(original_destination)


def build_url_entries(urls: List[str]) -> List[Dict[str, str]]:
    """Build URL entries with original, decoded (if present), and type."""
    entries: List[Dict[str, str]] = []

    for url in urls:
        entry = {
            "original_url": url,
            "url_type": "Direct URL",
            "decoded_url": "",
            "decode_status": "",
        }

        try:
            parsed = urlparse(url)
        except ValueError:
            entry["url_type"] = "Unparseable URL"
            entry["decode_status"] = "Could not parse URL. Kept original URL."
            entries.append(entry)
            continue

        hostname = (parsed.hostname or "").lower()
        if hostname.endswith("safelinks.protection.outlook.com"):
            entry["url_type"] = "Safe Link"
            decoded_url = decode_safe_link_url(url)
            if decoded_url:
                entry["decoded_url"] = decoded_url
            else:
                entry["decode_status"] = "Safe Link detected, but no decodable url parameter was found."

        entries.append(entry)

    return entries


def normalize_filename(filename: str | None) -> str:
    """Return a readable filename value, or Not found when absent."""
    if not filename:
        return "Not found"

    decoded_filename = decode_header_value(filename)
    if decoded_filename == "(not provided)":
        return "Not found"
    return decoded_filename


def is_inline_content_part(part) -> bool:
    """Return True when a message part is explicitly marked inline."""
    disposition = (part.get_content_disposition() or "").lower()
    return disposition == "inline"


def is_true_attachment_part(part) -> bool:
    """Return True when a message part should be treated as an attachment."""
    disposition = (part.get_content_disposition() or "").lower()
    if disposition == "attachment":
        return True

    if disposition == "inline":
        return False

    # Some emails omit attachment disposition but still provide a filename.
    return bool(part.get_filename())


def get_attachment_bytes(part) -> bytes:
    """Return decoded attachment bytes without saving or executing content."""
    payload = part.get_payload(decode=True)
    return payload if isinstance(payload, bytes) else b""


def hash_bytes_sha256(content: bytes) -> str:
    """Compute SHA-256 hash for attachment bytes."""
    return hashlib.sha256(content).hexdigest()


def build_attachment_entry(part) -> Dict[str, object]:
    """Build a metadata dictionary for one attachment part."""
    filename = normalize_filename(part.get_filename())
    content_type = part.get_content_type() or "application/octet-stream"
    attachment_bytes = get_attachment_bytes(part)

    return {
        "filename": filename,
        "content_type": content_type,
        "size_bytes": len(attachment_bytes),
        "sha256": hash_bytes_sha256(attachment_bytes),
    }


def extract_content_parts(message) -> Dict[str, List[Dict[str, object]]]:
    """Extract safe metadata for true attachments and inline content."""
    attachments: List[Dict[str, object]] = []
    inline_content: List[Dict[str, object]] = []

    if not message.is_multipart():
        return {"attachments": attachments, "inline_content": inline_content}

    for part in message.walk():
        if part.is_multipart():
            continue

        if is_inline_content_part(part):
            inline_content.append(build_attachment_entry(part))
            continue

        if is_true_attachment_part(part):
            attachments.append(build_attachment_entry(part))

    return {"attachments": attachments, "inline_content": inline_content}


def build_summary_data(message) -> Dict[str, object]:
    """Extract a simple summary dictionary from the parsed email."""
    sender = format_address_line(message.get("From"))
    recipient = format_address_line(message.get("To"))
    subject = decode_header_value(message.get("Subject"))
    sent_date = decode_header_value(message.get("Date"))

    body_text = extract_plain_text_body(message)
    preview = make_body_preview(body_text)
    urls = extract_urls(body_text)
    url_entries = build_url_entries(urls)
    content_parts = extract_content_parts(message)
    attachments = content_parts["attachments"]
    inline_content = content_parts["inline_content"]
    authentication_results = get_all_headers_or_not_found(message, "Authentication-Results")
    return_path = get_header_or_not_found(message, "Return-Path")
    reply_to = format_address_line(message.get("Reply-To"))
    received_headers = get_all_headers_or_not_found(message, "Received")
    received_routes = build_received_route_details(received_headers)
    likely_originating_ip = find_likely_originating_ip(received_routes)
    likely_originating_ip_note = get_likely_originating_ip_note(likely_originating_ip)
    last_sending_relay_ip = find_last_sending_relay_ip(received_routes)
    last_sending_relay_ip_note = get_last_sending_relay_ip_note(last_sending_relay_ip)
    auth_protocol_results = parse_authentication_results(authentication_results)

    return {
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "sent_date": sent_date,
        "body_preview": preview,
        "urls": urls,
        "url_entries": url_entries,
        "attachments": attachments,
        "inline_content": inline_content,
        "authentication_results": authentication_results,
        "return_path": return_path,
        "reply_to": reply_to,
        "received_headers": received_headers,
        "received_routes": received_routes,
        "likely_originating_ip": likely_originating_ip,
        "likely_originating_ip_note": likely_originating_ip_note,
        "last_sending_relay_ip": last_sending_relay_ip,
        "last_sending_relay_ip_note": last_sending_relay_ip_note,
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
    url_entries = summary["url_entries"]
    attachments = summary["attachments"]
    inline_content = summary["inline_content"]
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

    if url_entries:
        for index, entry in enumerate(url_entries, start=1):
            lines.append(f"### URL {index}")
            lines.append("")
            lines.append(f"- **Original URL:** {entry['original_url']}")
            if entry["decoded_url"]:
                lines.append(f"- **Decoded URL:** {entry['decoded_url']}")
            lines.append(f"- **URL Type:** {entry['url_type']}")
            if entry["decode_status"]:
                lines.append(f"- **Decode Status:** {entry['decode_status']}")
            lines.append("")
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Inline/Embedded Content",
            "",
        ]
    )

    if inline_content:
        for index, embedded_part in enumerate(inline_content, start=1):
            lines.extend(
                [
                    f"### Inline Item {index}",
                    "",
                    f"- **Filename:** {embedded_part['filename']}",
                    f"- **Content Type:** {embedded_part['content_type']}",
                    f"- **File Size (bytes):** {embedded_part['size_bytes']}",
                    f"- **SHA-256:** {embedded_part['sha256']}",
                    "",
                ]
            )
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Attachments Found",
            "",
        ]
    )

    if attachments:
        for index, attachment in enumerate(attachments, start=1):
            lines.extend(
                [
                    f"### Attachment {index}",
                    "",
                    f"- **Filename:** {attachment['filename']}",
                    f"- **Content Type:** {attachment['content_type']}",
                    f"- **File Size (bytes):** {attachment['size_bytes']}",
                    f"- **SHA-256:** {attachment['sha256']}",
                    "",
                ]
            )
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
            f"  - {summary['likely_originating_ip_note']}",
            f"- **Last Sending Relay Before Recipient Mail Server:** {summary['last_sending_relay_ip']}",
            f"  - {summary['last_sending_relay_ip_note']}",
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


def process_eml_file(eml_path: Path) -> None:
    """Parse one .eml file and write its Markdown triage report."""
    report_path = resolve_report_path(eml_path)

    if not eml_path.exists():
        print(f"Error: file not found: {eml_path}")
        return

    raw_email = read_eml_bytes(eml_path)
    message = parse_email(raw_email)
    summary = build_summary_data(message)

    print_summary(summary)

    report_content = build_markdown_report(summary)
    write_markdown_report(report_path, report_content)
    print(f"\nMarkdown report saved to: {report_path}")


def is_stable_for_processing(file_path: Path, wait_seconds: int = FILE_STABLE_WAIT_SECONDS) -> bool:
    """Check if file size is unchanged after a short wait."""
    try:
        first_size = file_path.stat().st_size
    except OSError:
        return False

    time.sleep(wait_seconds)

    try:
        second_size = file_path.stat().st_size
    except OSError:
        return False

    return first_size == second_size


def list_eml_files(folder_path: Path) -> List[Path]:
    """Return .eml files in a folder (non-recursive), sorted by name."""
    eml_files = [
        path for path in folder_path.iterdir() if path.is_file() and path.suffix.lower() == ".eml"
    ]
    return sorted(eml_files, key=lambda path: path.name.lower())


def run_watch_mode(watch_folder: Path) -> None:
    """Watch a folder for new .eml files and process each one once."""
    if not watch_folder.exists() or not watch_folder.is_dir():
        print(f"Error: watch folder not found: {watch_folder}")
        sys.exit(1)

    processed_files = {path.resolve() for path in list_eml_files(watch_folder)}
    print(f"Watching folder for new .eml files: {watch_folder}")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            for eml_file in list_eml_files(watch_folder):
                eml_file = eml_file.resolve()

                if eml_file in processed_files:
                    continue

                print(f"\nDetected new .eml file: {eml_file}")

                if not is_stable_for_processing(eml_file):
                    print("File still changing. Will try again on next scan.")
                    continue

                try:
                    process_eml_file(eml_file)
                except Exception as error:
                    print(f"Error processing {eml_file}: {error}")

                processed_files.add(eml_file)

            time.sleep(WATCH_POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nStopped watch mode.")


def main() -> None:
    """Entry point for single-file parsing or folder watch mode."""
    try:
        cli_options = parse_cli_args()
    except ValueError as error:
        print(error)
        sys.exit(1)

    if cli_options["mode"] == "watch":
        run_watch_mode(cli_options["watch_folder"])
        return

    eml_path = cli_options["eml_path"]
    if not eml_path.exists():
        print(f"Error: file not found: {eml_path}")
        sys.exit(1)

    process_eml_file(eml_path)


if __name__ == "__main__":
    main()
