import io
import sys
import unittest
from contextlib import redirect_stdout
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch


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

    def test_html_report_keeps_raw_received_headers_in_advanced_details(self) -> None:
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.edu"
        message["Received"] = "from relay.example (relay.example [198.51.100.7]) by recipient.example; Wed, 1 Jan 2025 00:00:00 +0000"
        message.set_content("Body text")

        report = main.build_html_report(main.build_summary_data(message))

        self.assertIn("Advanced: Raw Received Headers", report)
        self.assertIn("Raw Received Headers", report)
        self.assertIn("relay.example", report)
        self.assertNotIn("Received Header Public Originating IP", report)

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
        self.assertIn("Watching folder:", console_output.getvalue())
        self.assertIn("New .eml file detected: new_email.eml", console_output.getvalue())
        self.assertIn("new_email_report_2.md", console_output.getvalue())
        self.assertIn("Stopped watching folder.", console_output.getvalue())


if __name__ == "__main__":
    unittest.main()
