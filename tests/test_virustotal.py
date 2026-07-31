import json
import socket
import sys
import time
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import main
from reputation.models import (
    AttachmentReputationItem,
    AttachmentReputationSummary,
    ReputationResult,
    URLReputationItem,
    URLReputationSummary,
)
from reputation.service import (
    ReputationService,
    prepare_attachment_reputation_targets,
    prepare_url_reputation_targets,
)
from reputation.virustotal import (
    VirusTotalURLClient,
    _REQUEST_TIMESTAMPS,
    build_virustotal_url_id,
)


def virustotal_payload(malicious: int = 0, suspicious: int = 0) -> dict:
    return {
        "data": {
            "id": "vt-report-id",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": 12,
                    "undetected": 68,
                    "timeout": 1,
                },
                "last_analysis_date": 1_700_000_000,
            },
        }
    }


def successful_item(target: dict[str, str], malicious: int = 0, suspicious: int = 0) -> URLReputationItem:
    return URLReputationItem(
        original_url=target["original_url"],
        lookup_url=target["lookup_url"],
        decoded_destination=target["decoded_destination"],
        provider="VirusTotal",
        status="Lookup successful",
        malicious=malicious,
        suspicious=suspicious,
        harmless=12,
        undetected=68,
        timeout=1,
        total_engines=81,
        last_analysis_date="2023-11-14T22:13:20+00:00",
        report_id="vt-report-id",
    )


def attachment_target(filename: str, sha256: str, size_bytes: int = 12) -> dict[str, object]:
    return {
        "filename": filename,
        "content_type": "application/pdf",
        "size_bytes": size_bytes,
        "sha256": sha256,
    }


def successful_attachment_item(
    target: dict[str, object], malicious: int = 0, suspicious: int = 0
) -> AttachmentReputationItem:
    return AttachmentReputationItem(
        sha256=str(target["sha256"]),
        filenames=list(target["filenames"]),
        content_types=list(target["content_types"]),
        sizes_bytes=list(target["sizes_bytes"]),
        provider="VirusTotal",
        status="Lookup successful",
        malicious=malicious,
        suspicious=suspicious,
        harmless=12,
        undetected=68,
        total_engines=80,
        last_analysis_date="2023-11-14T22:13:20+00:00",
    )


class VirusTotalURLTests(unittest.TestCase):
    def setUp(self) -> None:
        _REQUEST_TIMESTAMPS.clear()

    def test_url_id_uses_urlsafe_base64_without_padding(self) -> None:
        self.assertEqual(
            build_virustotal_url_id("https://example.com/path"),
            "aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRo",
        )

    def test_successful_zero_detection_lookup(self) -> None:
        response = MagicMock()
        response.read.return_value = json.dumps(virustotal_payload()).encode("utf-8")
        with patch("reputation.virustotal.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = response
            result = VirusTotalURLClient(api_key="test-key").lookup_url(
                "https://example.com", "https://example.com"
            )

        self.assertEqual(result.status, "Lookup successful")
        self.assertFalse(result.flagged)
        self.assertEqual(result.total_engines, 81)
        self.assertEqual(mock_urlopen.call_count, 1)

    def test_malicious_suspicious_and_combined_detections_are_flagged(self) -> None:
        cases = ((1, 0), (0, 1), (2, 3))
        for malicious, suspicious in cases:
            with self.subTest(malicious=malicious, suspicious=suspicious):
                response = MagicMock()
                response.read.return_value = json.dumps(
                    virustotal_payload(malicious, suspicious)
                ).encode("utf-8")
                with patch("reputation.virustotal.urlopen") as mock_urlopen:
                    mock_urlopen.return_value.__enter__.return_value = response
                    result = VirusTotalURLClient(api_key="test-key").lookup_url(
                        "https://example.com", "https://example.com"
                    )
                self.assertTrue(result.flagged)
                self.assertEqual(result.malicious, malicious)
                self.assertEqual(result.suspicious, suspicious)

    def test_missing_api_key_and_no_url_cases_do_not_request_provider(self) -> None:
        client = VirusTotalURLClient(api_key="")
        service = ReputationService(virustotal_client=client)

        missing_key = service.check_urls([{"original_url": "https://example.com"}])
        no_urls = service.check_urls([])

        self.assertIn("API key not configured", missing_key.status)
        self.assertEqual(no_urls.status, "URL Reputation: No URLs found")

    def test_unsupported_schemes_are_ignored(self) -> None:
        service = ReputationService(virustotal_client=VirusTotalURLClient(api_key="test-key"))
        result = service.check_urls(
            [
                {"original_url": "mailto:user@example.com"},
                {"original_url": "cid:image@example.com"},
                {"original_url": "data:text/plain,hello"},
                {"original_url": "javascript:alert(1)"},
            ]
        )

        self.assertEqual(result.status, "URL Reputation: No supported HTTP or HTTPS URLs found")
        self.assertEqual(result.total_supported_urls, 0)

    def test_duplicate_urls_and_safe_link_destination_use_one_lookup(self) -> None:
        client = MagicMock()
        client.is_configured = True
        service = ReputationService(virustotal_client=client)
        entries = [
            {"original_url": "https://example.com/path", "decoded_url": ""},
            {
                "original_url": "https://safelinks.protection.outlook.com/?url=example",
                "decoded_url": "https://example.com/path",
            },
        ]
        _, _, targets = prepare_url_reputation_targets(entries)
        client.lookup_url.return_value = successful_item(targets[0])

        result = service.check_urls(entries)

        client.lookup_url.assert_called_once_with(
            "https://example.com/path", "https://example.com/path", ""
        )
        self.assertEqual(result.total_unique_urls, 1)

    def test_safe_link_destination_is_used_and_original_is_preserved(self) -> None:
        entries = [
            {
                "original_url": "https://nam12.safelinks.protection.outlook.com/?url=encoded",
                "decoded_url": "https://destination.example/login",
            }
        ]
        _, _, targets = prepare_url_reputation_targets(entries)

        self.assertEqual(targets[0]["lookup_url"], "https://destination.example/login")
        self.assertEqual(
            targets[0]["original_url"],
            "https://nam12.safelinks.protection.outlook.com/?url=encoded",
        )

    def test_404_is_not_a_flag_or_provider_failure(self) -> None:
        error = HTTPError("https://api.example", 404, "Not found", {}, None)
        with patch("reputation.virustotal.urlopen", side_effect=error):
            result = VirusTotalURLClient(api_key="test-key").lookup_url(
                "https://example.com", "https://example.com"
            )

        self.assertTrue(result.no_report)
        self.assertFalse(result.failed)
        self.assertFalse(result.flagged)

    def test_auth_rate_timeout_network_and_server_failures_are_safe(self) -> None:
        cases = [
            (HTTPError("https://api.example", 401, "Unauthorized", {}, None), "authentication failed"),
            (HTTPError("https://api.example", 403, "Forbidden", {}, None), "authentication failed"),
            (HTTPError("https://api.example", 429, "Too many", {}, None), "rate limit reached"),
            (HTTPError("https://api.example", 500, "Error", {}, None), "provider returned an error"),
            (socket.timeout(), "request timed out"),
            (URLError("offline"), "network unavailable"),
        ]
        for error, expected_text in cases:
            with self.subTest(expected_text=expected_text):
                with patch("reputation.virustotal.urlopen", side_effect=error):
                    result = VirusTotalURLClient(api_key="test-key").lookup_url(
                        "https://example.com", "https://example.com"
                    )
                self.assertTrue(result.failed)
                self.assertTrue(result.stop_processing)
                self.assertIn(expected_text, result.status)

    def test_malformed_response_structures_fail_safely(self) -> None:
        malformed_payloads = [
            [],
            {},
            {"data": {}},
            {"data": {"attributes": {}}},
            {"data": {"attributes": {"last_analysis_stats": []}}},
        ]
        for payload in malformed_payloads:
            with self.subTest(payload=payload):
                response = MagicMock()
                response.read.return_value = json.dumps(payload).encode("utf-8")
                with patch("reputation.virustotal.urlopen") as mock_urlopen:
                    mock_urlopen.return_value.__enter__.return_value = response
                    result = VirusTotalURLClient(api_key="test-key").lookup_url(
                        "https://example.com", "https://example.com"
                    )
                self.assertTrue(result.failed)
                self.assertIn("malformed response", result.status)

    def test_budget_limits_each_report_to_four_attempts_and_marks_partial(self) -> None:
        client = MagicMock()
        client.is_configured = True
        service = ReputationService(virustotal_client=client)
        entries = [{"original_url": f"https://example.com/{index}"} for index in range(5)]

        def lookup(original_url: str, lookup_url: str, decoded_destination: str) -> URLReputationItem:
            return successful_item(
                {
                    "original_url": original_url,
                    "lookup_url": lookup_url,
                    "decoded_destination": decoded_destination,
                }
            )

        client.lookup_url.side_effect = lookup
        result = service.check_urls(entries)

        self.assertEqual(client.lookup_url.call_count, 4)
        self.assertEqual(result.total_api_requests_attempted, 4)
        self.assertEqual(result.total_unchecked_urls, 1)
        self.assertTrue(result.partial)
        self.assertIn("current VirusTotal request limit", result.status)

    def test_process_budget_reduces_available_slots_for_watch_mode(self) -> None:
        _REQUEST_TIMESTAMPS.extend([time.time(), time.time()])
        client = MagicMock()
        client.is_configured = True
        service = ReputationService(virustotal_client=client)
        entries = [{"original_url": f"https://example.com/{index}"} for index in range(4)]

        client.lookup_url.side_effect = lambda original, lookup, decoded: successful_item(
            {"original_url": original, "lookup_url": lookup, "decoded_destination": decoded}
        )
        result = service.check_urls(entries)

        self.assertEqual(client.lookup_url.call_count, 2)
        self.assertEqual(result.total_unchecked_urls, 2)

    def test_partial_rate_limit_preserves_completed_flagged_result(self) -> None:
        client = MagicMock()
        client.is_configured = True
        service = ReputationService(virustotal_client=client)
        entries = [{"original_url": "https://first.example"}, {"original_url": "https://second.example"}]
        _, _, targets = prepare_url_reputation_targets(entries)
        client.lookup_url.side_effect = [
            successful_item(targets[0], malicious=1),
            URLReputationItem(
                original_url=targets[1]["original_url"],
                lookup_url=targets[1]["lookup_url"],
                decoded_destination="",
                provider="VirusTotal",
                status="Lookup failed - VirusTotal rate limit reached",
                failed=True,
                stop_processing=True,
                rate_limited=True,
            ),
        ]

        result = service.check_urls(entries)

        self.assertEqual(result.total_flagged_urls, 1)
        self.assertTrue(result.partial)
        self.assertTrue(result.rate_limit_reached)
        self.assertIn("rate limit reached", result.status)

    def test_timeout_after_completed_result_marks_lookup_partial(self) -> None:
        client = MagicMock()
        client.is_configured = True
        service = ReputationService(virustotal_client=client)
        entries = [{"original_url": "https://first.example"}, {"original_url": "https://second.example"}]
        _, _, targets = prepare_url_reputation_targets(entries)
        client.lookup_url.side_effect = [
            successful_item(targets[0]),
            URLReputationItem(
                original_url=targets[1]["original_url"],
                lookup_url=targets[1]["lookup_url"],
                decoded_destination="",
                provider="VirusTotal",
                status="Lookup failed - request timed out",
                failed=True,
                stop_processing=True,
            ),
        ]

        result = service.check_urls(entries)

        self.assertTrue(result.partial)
        self.assertEqual(result.total_successfully_checked_urls, 1)
        self.assertEqual(result.total_failed_urls, 1)
        self.assertIn("request timed out", result.status)

    def test_html_only_lists_flagged_urls_in_a_closed_dropdown(self) -> None:
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.edu"
        message.set_content("Body")
        summary = main.build_summary_data(message)
        flagged = URLReputationItem(
            original_url="https://example.com/?q=<script>",
            lookup_url="https://example.com/?q=<script>",
            decoded_destination="",
            provider="VirusTotal",
            status="Lookup successful",
            malicious=1,
            harmless=12,
            undetected=68,
            total_engines=81,
        )
        unflagged = URLReputationItem(
            original_url="https://not-listed.example",
            lookup_url="https://not-listed.example",
            decoded_destination="",
            provider="VirusTotal",
            status="Lookup successful",
        )
        url_summary = URLReputationSummary(
            status="URL Reputation: 1 of 2 checked URLs flagged by VirusTotal",
            total_extracted_urls=2,
            total_supported_urls=2,
            total_unique_urls=2,
            total_flagged_urls=1,
            complete=True,
            flagged_results=[flagged, unflagged],
        ).as_dict()
        summary["reputation_checks"] = {
            "sender_ip": {},
            "domain": {},
            "url": url_summary,
            "attachment_hash": {},
        }

        report = main.build_html_report(summary)

        self.assertIn(
            '<details class="collapsible reputation-details">\n<summary>URL Reputation</summary>', report
        )
        self.assertIn(
            '<details class="collapsible reputation-details">\n<summary>Sender IP Reputation</summary>', report
        )
        self.assertIn(
            '<details class="collapsible reputation-details">\n<summary>Domain Registration</summary>', report
        )
        self.assertIn("<h3>Flagged URLs</h3>", report)
        self.assertIn("<th>Detection result</th><td>1 URL flagged by VirusTotal vendors</td>", report)
        self.assertIn("&lt;script&gt;", report)
        self.assertNotIn("https://not-listed.example", report)

    def test_html_keeps_url_dropdown_when_nothing_is_flagged(self) -> None:
        message = EmailMessage()
        message.set_content("Body")
        summary = main.build_summary_data(message)
        summary["reputation_checks"] = {
            "sender_ip": {},
            "domain": {},
            "url": URLReputationSummary(
                status="URL Reputation: 1 unique URLs checked - none flagged by VirusTotal",
                total_extracted_urls=1,
                total_supported_urls=1,
                total_unique_urls=1,
                total_successfully_checked_urls=1,
                complete=True,
            ).as_dict(),
            "attachment_hash": {},
        }

        report = main.build_html_report(summary)

        self.assertIn("Lookup successful", report)
        self.assertIn("<th>URLs checked</th><td>1 of 1</td>", report)
        self.assertIn("<th>Detection result</th><td>None flagged by VirusTotal</td>", report)
        self.assertNotIn("<th>Unique URLs found</th>", report)
        self.assertNotIn("<th>Reports not found</th>", report)
        self.assertNotIn("<th>Results complete</th>", report)
        self.assertIn("<summary>URL Reputation</summary>", report)

    def test_html_flagged_safe_link_shows_original_and_decoded_destination(self) -> None:
        message = EmailMessage()
        message.set_content("Body")
        summary = main.build_summary_data(message)
        flagged = URLReputationItem(
            original_url="https://nam12.safelinks.protection.outlook.com/?url=encoded",
            lookup_url="https://destination.example/path",
            decoded_destination="https://destination.example/path",
            provider="VirusTotal",
            status="Lookup successful",
            suspicious=1,
        )
        summary["reputation_checks"] = {
            "sender_ip": {},
            "domain": {},
            "url": URLReputationSummary(
                status="URL Reputation: 1 of 1 checked URLs flagged by VirusTotal",
                total_extracted_urls=1,
                total_supported_urls=1,
                total_unique_urls=1,
                total_flagged_urls=1,
                complete=True,
                flagged_results=[flagged],
            ).as_dict(),
            "attachment_hash": {},
        }

        report = main.build_html_report(summary)

        self.assertIn("Original Safe Link", report)
        self.assertIn("Decoded destination", report)
        self.assertIn("Checked URL", report)
        self.assertIn("https://destination.example/path", report)

    def test_html_partial_url_summary_uses_compact_coverage_and_detection_wording(self) -> None:
        message = EmailMessage()
        message.set_content("Body")
        summary = main.build_summary_data(message)
        summary["reputation_checks"] = {
            "sender_ip": {},
            "domain": {},
            "url": URLReputationSummary(
                status=(
                    "URL Reputation: 2 of 4 unique URLs checked - none flagged in "
                    "completed lookups; 2 URLs not checked because of the current "
                    "VirusTotal request limit"
                ),
                total_extracted_urls=4,
                total_supported_urls=4,
                total_unique_urls=4,
                total_successfully_checked_urls=2,
                total_unchecked_urls=2,
                partial=True,
            ).as_dict(),
            "attachment_hash": {},
        }

        report = main.build_html_report(summary)

        self.assertIn(
            "<th>Lookup status</th><td>Partially checked - request limit reached</td>", report
        )
        self.assertIn("<th>URLs checked</th><td>2 of 4</td>", report)
        self.assertIn(
            "<th>Detection result</th><td>None flagged in completed lookups</td>", report
        )

    def test_html_multiple_flagged_urls_show_only_flagged_details(self) -> None:
        message = EmailMessage()
        message.set_content("Body")
        summary = main.build_summary_data(message)
        flagged_results = [
            URLReputationItem(
                original_url="https://one.example/" + ("a" * 250),
                lookup_url="https://one.example/" + ("a" * 250),
                decoded_destination="",
                provider="VirusTotal",
                status="Lookup successful",
                malicious=1,
            ),
            URLReputationItem(
                original_url="https://two.example",
                lookup_url="https://two.example",
                decoded_destination="",
                provider="VirusTotal",
                status="Lookup successful",
                suspicious=1,
            ),
        ]
        summary["reputation_checks"] = {
            "sender_ip": {},
            "domain": {},
            "url": URLReputationSummary(
                status="URL Reputation: 2 of 3 checked URLs flagged by VirusTotal",
                total_extracted_urls=3,
                total_supported_urls=3,
                total_unique_urls=3,
                total_flagged_urls=2,
                complete=True,
                flagged_results=flagged_results,
            ).as_dict(),
            "attachment_hash": {},
        }

        report = main.build_html_report(summary)

        self.assertIn("<th>Detection result</th><td>2 URLs flagged by VirusTotal vendors</td>", report)
        self.assertIn("Flagged URL 1", report)
        self.assertIn("Flagged URL 2", report)
        self.assertIn("Harmless detections", report)
        self.assertIn("overflow-wrap: anywhere", report)


class VirusTotalAttachmentTests(unittest.TestCase):
    def setUp(self) -> None:
        _REQUEST_TIMESTAMPS.clear()

    def test_file_lookup_uses_existing_sha256_report_without_uploading(self) -> None:
        sha256 = "a" * 64
        response = MagicMock()
        response.read.return_value = json.dumps(virustotal_payload()).encode("utf-8")
        with patch("reputation.virustotal.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = response
            result = VirusTotalURLClient(api_key="test-key").lookup_file_hash(
                sha256, ["invoice.pdf"], ["application/pdf"], [12]
            )

        request = mock_urlopen.call_args.args[0]
        self.assertEqual(request.full_url, f"https://www.virustotal.com/api/v3/files/{sha256}")
        self.assertIsNone(request.data)
        self.assertEqual(result.status, "Lookup successful")
        self.assertFalse(result.flagged)

    def test_attachment_target_selection_deduplicates_hashes_and_excludes_empty_parts(self) -> None:
        shared_hash = "a" * 64
        attachments = [
            attachment_target("first.pdf", shared_hash),
            attachment_target("second.pdf", shared_hash),
            attachment_target("empty.bin", "b" * 64, size_bytes=0),
            attachment_target("invalid.bin", "not-a-hash"),
        ]

        normal_count, targets = prepare_attachment_reputation_targets(attachments)

        self.assertEqual(normal_count, 4)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["filenames"], ["first.pdf", "second.pdf"])

    def test_parser_keeps_inline_content_out_of_normal_attachment_targets(self) -> None:
        message = EmailMessage()
        message.set_content("Body")
        message.add_attachment(b"normal", maintype="application", subtype="pdf", filename="invoice.pdf")
        message.add_attachment(
            b"inline-image", maintype="image", subtype="png", filename="logo.png", disposition="inline"
        )

        content_parts = main.extract_content_parts(message)
        normal_count, targets = prepare_attachment_reputation_targets(content_parts["attachments"])

        self.assertEqual(normal_count, 1)
        self.assertEqual(len(targets), 1)
        self.assertEqual(content_parts["inline_content"][0]["filename"], "logo.png")

    def test_attachment_missing_key_and_inline_only_states_do_not_request_provider(self) -> None:
        client = MagicMock()
        client.is_configured = False
        service = ReputationService(virustotal_client=client)
        valid_attachment = attachment_target("invoice.pdf", "a" * 64)

        missing_key = service.check_attachments([valid_attachment])
        inline_only = service.check_attachments([], [{"filename": "logo.png"}])

        self.assertIn("API key not configured", missing_key.status)
        self.assertEqual(missing_key.total_unchecked_hashes, 1)
        self.assertIn("no file attachments found", inline_only.status)
        self.assertTrue(inline_only.inline_content_present)
        client.lookup_file_hash.assert_not_called()

    def test_shared_budget_alternates_attachment_then_url_and_never_exceeds_four(self) -> None:
        client = MagicMock()
        client.is_configured = True
        service = ReputationService(virustotal_client=client)
        attachment_hashes = ["a" * 64, "b" * 64, "c" * 64]
        attachments = [attachment_target(f"file-{index}.pdf", value) for index, value in enumerate(attachment_hashes)]
        urls = [{"original_url": f"https://example.com/{index}"} for index in range(3)]
        _, _, prepared_urls = prepare_url_reputation_targets(urls)
        _, prepared_attachments = prepare_attachment_reputation_targets(attachments)
        client.lookup_file_hash.side_effect = [
            successful_attachment_item(prepared_attachments[0]),
            successful_attachment_item(prepared_attachments[1]),
        ]
        client.lookup_url.side_effect = [
            successful_item(prepared_urls[0]),
            successful_item(prepared_urls[1]),
        ]

        url_result, attachment_result = service._check_shared_virustotal_indicators(urls, attachments, [])

        self.assertEqual(client.lookup_file_hash.call_count, 2)
        self.assertEqual(client.lookup_url.call_count, 2)
        self.assertEqual(
            [call[0] for call in client.method_calls if call[0].startswith("lookup_")],
            ["lookup_file_hash", "lookup_url", "lookup_file_hash", "lookup_url"],
        )
        self.assertEqual(url_result.total_unchecked_urls, 1)
        self.assertEqual(attachment_result.total_unchecked_hashes, 1)

    def test_file_404_is_not_flagged_or_detailed_in_html(self) -> None:
        sha256 = "a" * 64
        error = HTTPError("https://api.example", 404, "Not found", {}, None)
        with patch("reputation.virustotal.urlopen", side_effect=error):
            item = VirusTotalURLClient(api_key="test-key").lookup_file_hash(
                sha256, ["unknown.bin"], ["application/octet-stream"], [12]
            )
        self.assertTrue(item.no_report)
        self.assertFalse(item.flagged)
        self.assertFalse(item.failed)

    def test_html_attachment_reputation_is_closed_and_lists_only_flagged_entries(self) -> None:
        message = EmailMessage()
        message.set_content("Body")
        summary = main.build_summary_data(message)
        flagged = AttachmentReputationItem(
            sha256="a" * 64,
            filenames=["bad<script>.exe", "duplicate.exe"],
            content_types=["application/octet-stream"],
            sizes_bytes=[123],
            provider="VirusTotal",
            status="Lookup successful",
            malicious=1,
        )
        unflagged = AttachmentReputationItem(
            sha256="b" * 64,
            filenames=["not-listed.pdf"],
            content_types=["application/pdf"],
            sizes_bytes=[10],
            provider="VirusTotal",
            status="Lookup successful",
        )
        summary["reputation_checks"] = {
            "sender_ip": {}, "domain": {}, "url": {},
            "attachment_hash": AttachmentReputationSummary(
                status="Attachment Hash Reputation: 1 of 2 checked hashes flagged by VirusTotal",
                total_normal_attachments=3,
                total_unique_hashes=2,
                total_flagged_hashes=1,
                complete=True,
                flagged_results=[flagged, unflagged],
            ).as_dict(),
        }

        report = main.build_html_report(summary)

        self.assertIn(
            '<details class="collapsible reputation-details">\n<summary>Attachment Hash Reputation</summary>', report
        )
        self.assertIn("<th>Attachments checked</th><td>2 of 2</td>", report)
        self.assertIn("1 attachment flagged by VirusTotal vendors", report)
        self.assertIn("<h3>Flagged Attachments</h3>", report)
        self.assertIn("bad&lt;script&gt;.exe", report)
        self.assertNotIn("not-listed.pdf", report)
        self.assertIn("overflow-wrap: anywhere", report)

    def test_shared_rate_limit_stops_both_indicator_types(self) -> None:
        client = MagicMock()
        client.is_configured = True
        service = ReputationService(virustotal_client=client)
        attachments = [attachment_target("blocked.exe", "a" * 64)]
        urls = [{"original_url": "https://example.com"}]
        _, prepared_attachments = prepare_attachment_reputation_targets(attachments)
        client.lookup_file_hash.return_value = AttachmentReputationItem(
            sha256=prepared_attachments[0]["sha256"],
            filenames=prepared_attachments[0]["filenames"],
            content_types=prepared_attachments[0]["content_types"],
            sizes_bytes=prepared_attachments[0]["sizes_bytes"],
            provider="VirusTotal",
            status="Lookup failed - VirusTotal rate limit reached",
            failed=True,
            stop_processing=True,
            rate_limited=True,
        )

        url_result, attachment_result = service._check_shared_virustotal_indicators(urls, attachments, [])

        client.lookup_url.assert_not_called()
        self.assertTrue(attachment_result.rate_limit_reached)
        self.assertTrue(url_result.rate_limit_reached)
        self.assertEqual(url_result.total_unchecked_urls, 1)

    def test_shared_authentication_failure_stops_both_indicator_types(self) -> None:
        client = MagicMock()
        client.is_configured = True
        service = ReputationService(virustotal_client=client)
        attachments = [attachment_target("blocked.exe", "a" * 64)]
        urls = [{"original_url": "https://example.com"}]
        _, prepared_attachments = prepare_attachment_reputation_targets(attachments)
        client.lookup_file_hash.return_value = AttachmentReputationItem(
            sha256=prepared_attachments[0]["sha256"],
            filenames=prepared_attachments[0]["filenames"],
            content_types=prepared_attachments[0]["content_types"],
            sizes_bytes=prepared_attachments[0]["sizes_bytes"],
            provider="VirusTotal",
            status="Lookup failed - VirusTotal authentication failed",
            failed=True,
            stop_processing=True,
            authentication_failed=True,
        )

        url_result, attachment_result = service._check_shared_virustotal_indicators(urls, attachments, [])

        client.lookup_url.assert_not_called()
        self.assertIn("authentication failed", url_result.status)
        self.assertIn("authentication failed", attachment_result.status)


if __name__ == "__main__":
    unittest.main()
