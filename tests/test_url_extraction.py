import sys
import unittest
from email.message import EmailMessage
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
