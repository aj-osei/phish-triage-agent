import json
import os
import socket
import sys
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import main
from reputation.abuseipdb import AbuseIPDBClient
from reputation.models import ReputationResult
from reputation.service import ReputationService, build_unchecked_reputation_checks


class AbuseIPDBTests(unittest.TestCase):
    def test_successful_lookup_normalizes_response(self) -> None:
        response = MagicMock()
        response.read.return_value = json.dumps(
            {
                "data": {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 25,
                    "totalReports": 4,
                    "countryName": "United States",
                    "countryCode": "US",
                    "city": "New York",
                    "isp": "Example ISP",
                    "domain": "example.net",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "lastReportedAt": "2026-07-22T12:00:00+00:00",
                    "reports": [
                        {"categories": [7, 11]},
                        {"categories": [11, 17]},
                        {"categories": [7]},
                    ],
                }
            }
        ).encode("utf-8")
        with patch("reputation.abuseipdb.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = response
            result = AbuseIPDBClient(api_key="test-key").lookup_sender_ip("8.8.8.8")

        self.assertEqual(result.status, "Lookup successful")
        self.assertEqual(result.provider, "AbuseIPDB")
        self.assertEqual(result.details["Abuse confidence score"], "25")
        self.assertEqual(result.details["Total reports"], "4")
        self.assertEqual(result.details["Last reported date"], "2026-07-22T12:00:00+00:00")
        self.assertEqual(result.details["ISP"], "Example ISP")
        self.assertEqual(result.details["Usage type"], "Data Center/Web Hosting/Transit")
        self.assertEqual(result.details["Country name"], "United States")
        self.assertEqual(result.details["City"], "New York")
        self.assertEqual(
            result.details["Reported activity"], "Phishing, Email Spam, Spoofing"
        )
        self.assertEqual(mock_urlopen.call_count, 1)
        request_url = mock_urlopen.call_args.args[0].full_url
        self.assertIn("verbose=true", request_url)
        self.assertIn("maxAgeInDays=90", request_url)

    def test_city_is_neutral_when_provider_does_not_return_it(self) -> None:
        response = MagicMock()
        response.read.return_value = json.dumps(
            {
                "data": {
                    "ipAddress": "8.8.8.8",
                    "countryCode": "ZZ",
                    "totalReports": 0,
                    "reports": [],
                }
            }
        ).encode("utf-8")
        with patch("reputation.abuseipdb.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = response
            result = AbuseIPDBClient(api_key="test-key").lookup_sender_ip("8.8.8.8")

        self.assertEqual(result.details["City"], "Not found")
        self.assertEqual(result.details["Total reports"], "0")
        self.assertEqual(result.details["Reported activity"], "Not found")
        self.assertEqual(main.format_country_name("ZZ"), "ZZ")

    def test_report_activity_handles_unknown_and_malformed_categories(self) -> None:
        response = MagicMock()
        response.read.return_value = json.dumps(
            {
                "data": {
                    "ipAddress": "8.8.8.8",
                    "totalReports": 99,
                    "reports": [
                        {"categories": [24, 7, 24]},
                        {"categories": "not a list"},
                        {"categories": ["11", None]},
                        {},
                    ],
                }
            }
        ).encode("utf-8")
        with patch("reputation.abuseipdb.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = response
            result = AbuseIPDBClient(api_key="test-key").lookup_sender_ip("8.8.8.8")

        self.assertEqual(result.details["Total reports"], "99")
        self.assertEqual(
            result.details["Reported activity"], "Phishing, Unknown category (24)"
        )

    def test_missing_api_key_skips_lookup(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch("reputation.abuseipdb.urlopen") as mock_urlopen:
            result = AbuseIPDBClient().lookup_sender_ip("8.8.8.8")

        self.assertEqual(result.status, "Not checked — API key not configured")
        mock_urlopen.assert_not_called()

    def test_missing_sender_ip_skips_lookup(self) -> None:
        with patch("reputation.abuseipdb.urlopen") as mock_urlopen:
            result = AbuseIPDBClient(api_key="test-key").lookup_sender_ip("Not found")

        self.assertEqual(result.status, "Not checked — sender IP unavailable")
        mock_urlopen.assert_not_called()

    def test_timeout_returns_readable_status(self) -> None:
        with patch("reputation.abuseipdb.urlopen", side_effect=socket.timeout):
            result = AbuseIPDBClient(api_key="test-key").lookup_sender_ip("8.8.8.8")

        self.assertEqual(result.status, "Lookup failed — request timed out")

    def test_provider_error_returns_readable_status(self) -> None:
        provider_error = HTTPError("https://example.invalid", 500, "Server error", {}, None)
        with patch("reputation.abuseipdb.urlopen", side_effect=provider_error):
            result = AbuseIPDBClient(api_key="test-key").lookup_sender_ip("8.8.8.8")

        self.assertEqual(result.status, "Lookup failed — provider returned an error")

    def test_malformed_response_returns_readable_status(self) -> None:
        response = MagicMock()
        response.read.return_value = b'{"unexpected": "response"}'
        with patch("reputation.abuseipdb.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = response
            result = AbuseIPDBClient(api_key="test-key").lookup_sender_ip("8.8.8.8")

        self.assertEqual(result.status, "Lookup failed — provider returned malformed response")

    def test_service_caches_sender_ip_lookup_for_one_run(self) -> None:
        client = MagicMock()
        client.lookup_sender_ip.return_value = ReputationResult(
            category="Sender IP Reputation",
            provider="AbuseIPDB",
            status="Lookup successful",
        )
        service = ReputationService(abuseipdb_client=client)

        service.check_sender_ip("8.8.8.8")
        service.check_sender_ip("8.8.8.8")

        client.lookup_sender_ip.assert_called_once_with("8.8.8.8")

    def test_html_report_generates_when_reputation_lookup_fails(self) -> None:
        failure_checks = build_unchecked_reputation_checks("8.8.8.8")
        failure_checks["sender_ip"]["status"] = "Lookup failed — request timed out"
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.edu"
        message.set_content("Test body")
        summary = main.build_summary_data(message)
        summary["reputation_checks"] = failure_checks

        report = main.build_html_report(summary)
        self.assertIn("Reputation Checks", report)
        self.assertIn("Lookup failed — request timed out", report)


if __name__ == "__main__":
    unittest.main()
