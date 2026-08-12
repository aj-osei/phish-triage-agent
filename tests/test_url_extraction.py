import io
import sys
import unittest
from contextlib import redirect_stdout
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import Mock, patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import main


class URLExtractionTests(unittest.TestCase):
    def test_html_attribute_urls_are_combined_with_plain_text_urls(self) -> None:
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.edu"
        message.set_content("Plain URL: https://plain.example/path")
        message.add_alternative(
            """
            <a href="https://plain.example/path">Duplicate plain URL</a>
            <img src="https://images.example/logo.png">
            <form action="https://forms.example/submit">
              <object data="https://objects.example/file"></object>
              <button formaction="https://buttons.example/send">Send</button>
            </form>
            Visible URL: https://visible.example/page
            <a href="https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Ftarget.example">Safe Link</a>
            """,
            subtype="html",
        )

        summary = main.build_summary_data(message)

        self.assertEqual(len(summary["urls"]), 7)
        self.assertEqual(summary["urls"].count("https://plain.example/path"), 1)
        self.assertIn("https://images.example/logo.png", summary["urls"])
        self.assertIn("https://forms.example/submit", summary["urls"])
        self.assertIn("https://objects.example/file", summary["urls"])
        self.assertIn("https://buttons.example/send", summary["urls"])
        self.assertIn("https://visible.example/page", summary["urls"])

        checks = {label: (status, detail) for label, status, detail in summary["quick_checks"]}
        self.assertEqual(checks["URLs"], ("Found", "7"))
        self.assertEqual(checks["Safe Links"], ("Found", "1"))

    def test_quick_check_authentication_statuses(self) -> None:
        cases = [
            (
                {"spf": "Not found", "dkim": "Not found", "dmarc": "Not found"},
                "Not found",
            ),
            (
                {"spf": "pass", "dkim": "fail", "dmarc": "pass"},
                "Failed",
            ),
            (
                {"spf": "pass", "dkim": "Not found", "dmarc": "pass"},
                "Partial",
            ),
            (
                {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
                "Passed",
            ),
            (
                {"spf": "pass", "dkim": "unknown", "dmarc": "pass"},
                "Partial",
            ),
        ]

        for results, expected_status in cases:
            with self.subTest(results=results):
                summary = {f"{protocol}_result": result for protocol, result in results.items()}
                checks = {
                    label: (status, detail)
                    for label, status, detail in main.build_quick_checks(summary)
                }
                status, detail = checks["Authentication"]
                self.assertEqual(status, expected_status)
                self.assertEqual(
                    detail,
                    f"SPF: {results['spf'].lower()} | DKIM: {results['dkim'].lower()} | "
                    f"DMARC: {results['dmarc'].lower()}",
                )

    def test_quick_check_return_path_statuses(self) -> None:
        cases = [
            ("sender@example.com", "Not found", "Not found"),
            ("sender@example.com", "sender@example.com", "Matches From"),
            ("sender@example.com", "bounce@example.com", "Matches From"),
            ("sender@example.com", "bounce@example.net", "Differs from From"),
            ("Not found", "bounce@example.net", "From not found"),
        ]

        for sender, return_path, expected_status in cases:
            with self.subTest(sender=sender, return_path=return_path):
                checks = {
                    label: (status, detail)
                    for label, status, detail in main.build_quick_checks(
                        {"sender": sender, "return_path": return_path}
                    )
                }
                status, detail = checks["Return-Path"]
                self.assertEqual(status, expected_status)
                self.assertEqual(
                    detail,
                    "From: "
                    f"{main.normalize_email_address(sender) or 'not found'} | Return-Path: "
                    f"{main.normalize_email_address(return_path) or 'not found'}",
                )

    def test_email_domain_parsing_handles_standard_and_exchange_style_addresses(self) -> None:
        cases = {
            "user@uab.edu": "uab.edu",
            "Example User <user@uab.edu>": "uab.edu",
            "Example User [user@uab.edu]": "uab.edu",
            " Example User <USER@UAB.EDU> ": "uab.edu",
            "sender@external.example": "external.example",
            "Not found": "",
            "not a mailbox": "",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(main.get_email_domain(value), expected)

        checks = {
            label: status
            for label, status, _ in main.build_quick_checks(
                {"sender": "Example User [user@uab.edu]", "recipient": "recipient@uab.edu"}
            )
        }
        self.assertEqual(checks["External sender"], "No")

    def test_sender_ip_uses_exchange_original_client_fallback_after_link_local_ip(self) -> None:
        message = EmailMessage()
        message["Authentication-Results"] = "mx.example; sender ip is fe80::54d:972f:e575:741c"
        message["x-ms-exchange-organization-originalclientipaddress"] = "[8.8.8.8]"

        result = main.find_sender_ip_analysis(message, [])

        self.assertEqual(result["sender_ip"], "8.8.8.8")
        self.assertEqual(
            result["sender_ip_source"],
            "X-MS-Exchange-Organization-OriginalClientIPAddress",
        )
        self.assertEqual(result["sender_ip_classification"], "Public IP")

    def test_sender_ip_accepts_public_ipv6_and_rejects_unusable_candidates(self) -> None:
        public_ipv6_message = EmailMessage()
        public_ipv6_message["Authentication-Results"] = (
            "mx.example; sender ip is 2001:4860:4860::8888"
        )
        self.assertEqual(
            main.find_sender_ip_analysis(public_ipv6_message, [])["sender_ip"],
            "2001:4860:4860::8888",
        )

        unusable_message = EmailMessage()
        unusable_message["Authentication-Results"] = "mx.example; sender ip is not-an-ip"
        unusable_message["X-Originating-IP"] = "[fe80::1]"
        result = main.find_sender_ip_analysis(unusable_message, [])
        self.assertEqual(result["sender_ip"], "Not found")
        self.assertEqual(result["sender_ip_source"], "Not found")

    def test_sender_ip_received_fallback_skips_local_hops_for_public_route(self) -> None:
        message = EmailMessage()
        routes = [
            {"source_ip": "8.8.4.4"},
            {"source_ip": "fe80::1"},
        ]

        result = main.find_sender_ip_analysis(message, routes)

        self.assertEqual(result["sender_ip"], "8.8.4.4")
        self.assertEqual(result["sender_ip_source"], "Received headers fallback")

    def test_html_report_uses_local_collapsible_ui_elements(self) -> None:
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.edu"
        message["Subject"] = "HTML report UI test"
        message.set_content(
            "Review https://example.com/a/very/long/path\n"
            "Second line with <script>untrusted text</script>."
        )

        report = main.build_html_report(main.build_summary_data(message))

        self.assertIn('class="section-card"', report)
        self.assertIn('class="quick-checks"', report)
        self.assertIn('<details class="collapsible">', report)
        self.assertIn("Subject: HTML report UI test", report)
        self.assertIn("View full body", report)
        self.assertIn("Second line with &lt;script&gt;untrusted text&lt;/script&gt;.", report)
        self.assertIn("No raw Received headers found.", report)
        self.assertNotIn("Local email triage", report)
        self.assertNotIn("<br>From:", report)
        self.assertNotIn("Received Header Public Originating IP", report)
        self.assertNotIn("<script", report.lower())
        self.assertNotIn("<a href=", report.lower())

    def test_html_moves_quick_checks_and_sender_ip_reputation_to_requested_locations(self) -> None:
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.edu"
        message.set_content("Body")
        summary = main.build_summary_data(message)
        summary["reputation_checks"] = {
            "sender_ip": {
                "category": "Sender IP Reputation",
                "provider": "AbuseIPDB",
                "status": "Lookup successful",
                "details": {
                    "Abuse confidence score": "25",
                    "Country name": "United States",
                    "Country code": "US",
                    "City": "New York",
                    "ISP": "Example ISP",
                },
            },
            "domain": {}, "url": {}, "attachment_hash": {},
        }
        report = main.build_html_report(summary)

        self.assertLess(report.index("<h2>Email Summary</h2>"), report.index("<h2>Quick Checks</h2>"))
        self.assertLess(report.index("<h2>Quick Checks</h2>"), report.index("<h2>Body Preview</h2>"))
        sender_analysis = report.index("<h2>Sender IP Analysis</h2>")
        sender_reputation = report.index("<h3>Sender IP Reputation</h3>")
        reputation_checks = report.index("<h2>Reputation Checks</h2>")
        self.assertLess(sender_analysis, sender_reputation)
        self.assertLess(sender_reputation, reputation_checks)
        self.assertEqual(report.count("<h3>Sender IP Reputation</h3>"), 1)
        self.assertIn("<th>Lookup Status</th>", report)
        self.assertIn("<th>Abuse Confidence</th>", report)
        self.assertIn("<th>Reports</th>", report)
        self.assertIn("<th>Last Reported</th>", report)
        self.assertIn("<th>Reported Activity</th>", report)
        self.assertIn("<th>ISP</th>", report)
        self.assertIn("<th>Usage Type</th>", report)
        self.assertIn("<th>Country</th><td>United States</td>", report)
        self.assertNotIn("<th>City</th>", report)
        self.assertNotIn("New York", report)
        self.assertIn("<h4>AbuseIPDB</h4>", report)
        self.assertIn("<th>Reported Activity</th><td>Not available</td>", report)
        self.assertNotIn("View reputation details", report)

    def test_abuse_confidence_uses_score_only_semantic_classes(self) -> None:
        message = EmailMessage(); message.set_content("Body")
        expectations = (
            ("0", "0", "finding-positive"),
            ("1", "1", "finding-caution"),
            ("74", "74", "finding-caution"),
            ("75", "75", "finding-attention"),
            ("100", "100", "finding-attention"),
            ("unavailable", "unavailable", "finding-neutral"),
            (None, "Not available", "finding-neutral"),
        )
        for score, displayed_score, css_class in expectations:
            with self.subTest(score=score):
                summary = main.build_summary_data(message)
                details = {} if score is None else {"Abuse confidence score": score}
                summary["reputation_checks"] = {
                    "sender_ip": {
                        "category": "Sender IP Reputation",
                        "provider": "AbuseIPDB",
                        "status": "Lookup successful",
                        "details": details,
                    },
                    "domain": {}, "url": {}, "attachment_hash": {},
                }
                report = main.build_html_report(summary)
                self.assertIn(
                    f'<th>Abuse Confidence</th><td class="{css_class}">{displayed_score}</td>', report
                )

    def test_html_report_keeps_raw_received_headers_in_advanced_details(self) -> None:
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.edu"
        message["Received"] = "from relay.example (relay.example [198.51.100.7]) by recipient.example with ESMTPS (TLS1.2); Wed, 1 Jan 2025 00:00:00 +0000"
        message.set_content("Body text")

        report = main.build_html_report(main.build_summary_data(message))

        self.assertIn("Advanced: Raw Received Headers", report)
        self.assertIn("Raw Received Headers", report)
        self.assertIn("relay.example", report)
        self.assertIn("Submitting host", report)
        self.assertIn("Receiving host", report)
        self.assertIn("Time", report)
        self.assertIn("Delay", report)
        self.assertIn("Type", report)
        self.assertIn("ESMTPS | TLS1.2", report)
        self.assertIn("<h3>Hop 1</h3>", report)
        self.assertNotIn("<th>Hop</th>", report)
        self.assertNotIn("Parsed from Received headers", report)
        self.assertNotIn("Received Header Public Originating IP", report)

    def test_received_hop_delay_calculation_uses_safe_fallbacks(self) -> None:
        routes = [
            {"timestamp": "Wed, 1 Jan 2025 00:00:00 +0000"},
            {"timestamp": "Wed, 1 Jan 2025 00:01:30 +0000"},
            {"timestamp": "Not found"},
        ]

        self.assertEqual(
            main.calculate_received_hop_delays(routes),
            ["Not calculated", "1m 30s", "Not calculated"],
        )

    def test_manual_folder_processing_honors_output_and_format(self) -> None:
        input_folder = Path("samples").resolve()
        output_folder = Path("custom_reports").resolve()
        eml_file = input_folder / "test_email.eml"
        result = {
            "input_file": eml_file,
            "markdown_report": output_folder / "test_email_report.md",
            "html_report": None,
            "error": None,
        }

        with (
            patch.object(main, "list_eml_files", return_value=[eml_file]),
            patch.object(main, "list_non_eml_files", return_value=[input_folder / "notes.txt"]),
            patch.object(main, "process_eml_file", return_value=result) as process_file,
        ):
            console_output = io.StringIO()
            with redirect_stdout(console_output):
                main.process_input_path(input_folder, output_folder, "md")

        process_file.assert_called_once_with(eml_file, output_folder, "md")
        self.assertIn("Skipped non-.eml file: notes.txt", console_output.getvalue())
        self.assertIn("Markdown report:", console_output.getvalue())

    def test_cli_parses_file_or_folder_options(self) -> None:
        options = main.parse_cli_args(["samples", "--output", "custom_reports", "--format", "html"])

        self.assertEqual(options["mode"], "manual")
        self.assertEqual(options["input_path"], Path("samples").resolve())
        self.assertEqual(options["output_folder"], Path("custom_reports").resolve())
        self.assertEqual(options["report_format"], "html")

    def test_cli_parses_watch_options(self) -> None:
        options = main.parse_cli_args(["--watch", "samples", "--output", "custom_reports"])

        self.assertEqual(options["mode"], "watch")
        self.assertEqual(options["watch_folder"], Path("samples").resolve())
        self.assertEqual(options["output_folder"], Path("custom_reports").resolve())
        self.assertEqual(options["report_format"], "both")

    def test_cli_parses_readiness_check_options(self) -> None:
        options = main.parse_cli_args(["--check", "--watch", "samples", "--output", "custom_reports"])

        self.assertEqual(options["mode"], "check")
        self.assertEqual(options["watch_folder"], Path("samples").resolve())
        self.assertEqual(options["output_folder"], Path("custom_reports").resolve())

    def test_watch_readiness_reports_configuration_without_printing_keys(self) -> None:
        watch_folder = Path("samples").resolve()
        output_folder = Path("reports").resolve()
        secret_abuseipdb = "abuseipdb-secret-value"
        secret_virustotal = "virustotal-secret-value"

        with patch.dict(
            main.os.environ,
            {
                "ABUSEIPDB_API_KEY": secret_abuseipdb,
                "VIRUSTOTAL_API_KEY": secret_virustotal,
            },
            clear=False,
        ):
            console_output = io.StringIO()
            with redirect_stdout(console_output):
                ready = main.print_watch_readiness(watch_folder, output_folder)

        output = console_output.getvalue()
        self.assertTrue(ready)
        self.assertIn(f"Phish Pharm {main.PROJECT_VERSION}", output)
        self.assertIn("Python:              Ready -", output)
        self.assertIn("AbuseIPDB:           Configured", output)
        self.assertIn("VirusTotal:          Configured", output)
        self.assertIn("RDAP:                Ready - no API key required", output)
        self.assertNotIn(secret_abuseipdb, output)
        self.assertNotIn(secret_virustotal, output)

    def test_watch_readiness_creates_folders_and_allows_missing_keys(self) -> None:
        watch_folder = Mock()
        watch_folder.is_dir.return_value = True
        watch_folder.__str__ = Mock(return_value="C:\\resolved\\Inbox")
        output_folder = Mock()
        output_folder.is_dir.return_value = True
        output_folder.__str__ = Mock(return_value="C:\\resolved\\Reports")
        with patch.dict(
            main.os.environ,
            {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""},
            clear=False,
        ):
            console_output = io.StringIO()
            with redirect_stdout(console_output):
                ready = main.print_watch_readiness(watch_folder, output_folder)

        output = console_output.getvalue()
        self.assertTrue(ready)
        watch_folder.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        output_folder.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        self.assertIn("Not configured - sender IP reputation will be skipped", output)
        self.assertIn("Not configured - URL and attachment reputation will be skipped", output)

    def test_watch_readiness_stops_when_inbox_cannot_be_prepared(self) -> None:
        failed_folder = Mock()
        failed_folder.mkdir.side_effect = OSError("access denied")
        failed_folder.__str__ = Mock(return_value="C:\\blocked\\Inbox")
        ready_folder = Path("samples").resolve()

        console_output = io.StringIO()
        with redirect_stdout(console_output):
            ready = main.print_watch_readiness(failed_folder, ready_folder)

        self.assertFalse(ready)
        self.assertIn("Inbox folder:        Failed - could not create folder", console_output.getvalue())
        self.assertIn("Watcher:             Not started", console_output.getvalue())

    def test_main_starts_watcher_once_when_keys_are_missing(self) -> None:
        options = {
            "mode": "watch",
            "watch_folder": Path("samples").resolve(),
            "output_folder": Path("reports").resolve(),
            "report_format": "html",
        }
        with (
            patch.object(main, "parse_cli_args", return_value=options),
            patch.object(main, "run_watch_mode") as run_watch_mode,
            patch.dict(
                main.os.environ,
                {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""},
                clear=False,
            ),
        ):
            console_output = io.StringIO()
            with redirect_stdout(console_output):
                main.main()

        output = console_output.getvalue()
        run_watch_mode.assert_called_once_with(
            options["watch_folder"], options["output_folder"], "html"
        )
        self.assertEqual(output.count(f"Phish Pharm {main.PROJECT_VERSION}"), 1)
        self.assertIn("Not configured - sender IP reputation will be skipped", output)
        self.assertIn("Not configured - URL and attachment reputation will be skipped", output)

    def test_main_does_not_start_watcher_when_readiness_fails(self) -> None:
        options = {
            "mode": "watch",
            "watch_folder": Path("samples").resolve(),
            "output_folder": Path("reports").resolve(),
            "report_format": "html",
        }
        with (
            patch.object(main, "parse_cli_args", return_value=options),
            patch.object(main, "print_watch_readiness", return_value=False),
            patch.object(main, "run_watch_mode") as run_watch_mode,
        ):
            main.main()

        run_watch_mode.assert_not_called()

    def test_paired_report_paths_use_the_same_available_suffix(self) -> None:
        existing_names = {
            "suspicious_report.md",
            "suspicious_report.html",
            "suspicious_report_1.md",
        }
        with patch.object(
            Path,
            "exists",
            autospec=True,
            side_effect=lambda path: path.name in existing_names,
        ):
            markdown_path, html_path = main.resolve_unique_report_paths(
                Path("suspicious.eml"), Path("reports"), "both"
            )

        self.assertEqual(markdown_path.name, "suspicious_report_2.md")
        self.assertEqual(html_path.name, "suspicious_report_2.html")

    def test_watch_mode_processes_a_new_stable_email_and_stops_cleanly(self) -> None:
        watch_folder = Path("samples").resolve()
        existing_file = watch_folder / "existing.eml"
        new_file = watch_folder / "new_email.eml"
        output_folder = Path("custom_reports").resolve()
        first_result = {
            "input_file": new_file,
            "markdown_report": output_folder / "new_email_report_1.md",
            "html_report": output_folder / "new_email_report_1.html",
            "error": None,
        }
        second_result = {
            "input_file": new_file,
            "markdown_report": output_folder / "new_email_report_2.md",
            "html_report": output_folder / "new_email_report_2.html",
            "error": None,
        }

        with (
            patch.object(
                main,
                "list_eml_files",
                side_effect=[
                    [existing_file],
                    [existing_file, new_file],
                    [existing_file],
                    [existing_file, new_file],
                ],
            ),
            patch.object(
                main,
                "get_file_signature",
                side_effect=[(1, 1), (1, 1), (2, 2), (2, 2), (1, 1), (1, 1), (2, 2), (2, 2)],
            ),
            patch.object(main, "is_file_size_stable", return_value=True),
            patch.object(main, "process_eml_file", side_effect=[first_result, second_result]) as process_file,
            patch.object(main.time, "sleep", side_effect=[None, None, KeyboardInterrupt]),
        ):
            console_output = io.StringIO()
            with redirect_stdout(console_output):
                main.run_watch_mode(watch_folder, output_folder, "both")

        self.assertEqual(process_file.call_count, 2)
        process_file.assert_called_with(new_file.resolve(), output_folder, "both")
        self.assertIn("Watcher:             Running", console_output.getvalue())
        self.assertIn(str(watch_folder), console_output.getvalue())
        self.assertIn("New .eml file detected: new_email.eml", console_output.getvalue())
        self.assertIn("new_email_report_2.md", console_output.getvalue())
        self.assertIn("Stopped watching folder.", console_output.getvalue())


if __name__ == "__main__":
    unittest.main()
