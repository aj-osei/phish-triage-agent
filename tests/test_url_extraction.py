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

        self.assertEqual(options["input_path"], Path("samples").resolve())
        self.assertEqual(options["output_folder"], Path("custom_reports").resolve())
        self.assertEqual(options["report_format"], "html")


if __name__ == "__main__":
    unittest.main()
