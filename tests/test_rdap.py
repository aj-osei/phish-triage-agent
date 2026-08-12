import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import main
from reputation.models import DomainRegistrationResult
from reputation.rdap import RDAPClient, _BOOTSTRAP_CACHE, normalize_registered_domain
from reputation.service import ReputationService, prepare_domain_registration_targets


class RDAPTests(unittest.TestCase):
    def setUp(self) -> None:
        import reputation.rdap as rdap
        rdap._BOOTSTRAP_CACHE = None

    def test_domain_collection_uses_only_from_and_reply_to(self) -> None:
        summary = {
            "sender": "Sender <sender@login.example.co.uk>",
            "reply_to": "reply@example.co.uk",
            "return_path": "<bounce@example.net>",
            "url_entries": [
                {"original_url": "https://sub.example.co.uk/path", "decoded_url": ""},
                {"original_url": "https://safe.example/?url=x", "decoded_url": "https://login.example.co.uk"},
            ],
        }
        targets = prepare_domain_registration_targets(summary)
        co_uk = next(item for item in targets if item["registered_domain"] == "example.co.uk")
        self.assertEqual(co_uk["observed_hostnames"], ["login.example.co.uk", "example.co.uk"])
        self.assertEqual(co_uk["source_labels"], ["From", "Reply-To"])
        self.assertNotIn("example.net", [item["registered_domain"] for item in targets])
        self.assertEqual(len(targets), 1)

    def test_idn_and_ip_normalization(self) -> None:
        self.assertEqual(normalize_registered_domain("WWW.BÜCHER.DE."), ("www.xn--bcher-kva.de", "xn--bcher-kva.de"))
        self.assertIsNone(normalize_registered_domain("192.0.2.10"))
        self.assertIsNone(normalize_registered_domain("localhost"))

    def test_rdap_bootstrap_and_domain_response_normalize_age(self) -> None:
        registration = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        bootstrap = {"services": [[["com"], ["https://rdap.example/"]] ]}
        payload = {"data": "unused"}  # replaced below to make structure readable
        payload = {
            "handle": "DOMAIN-1", "events": [{"eventAction": "registration", "eventDate": registration}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
            "nameservers": [{"ldhName": "ns1.example.com"}], "status": ["active"],
        }
        responses = []
        for value in (bootstrap, payload):
            response = MagicMock(); response.read.return_value = json.dumps(value).encode("utf-8"); responses.append(response)
        with patch("reputation.rdap.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.side_effect = responses
            result = RDAPClient().lookup_domain("example.com", ["www.example.com"], ["URL"])
        self.assertEqual(result.status, "Lookup successful")
        self.assertEqual(result.registrar, "Example Registrar")
        self.assertTrue(result.recently_registered)
        self.assertEqual(result.nameservers, ["ns1.example.com"])

    def test_404_and_missing_reply_to_are_safe(self) -> None:
        bootstrap = {"services": [[["com"], ["https://rdap.example/"]] ]}
        response = MagicMock(); response.read.return_value = json.dumps(bootstrap).encode("utf-8")
        with patch("reputation.rdap.urlopen", side_effect=[MagicMock(__enter__=MagicMock(return_value=response)), HTTPError("x", 404, "missing", {}, None)]):
            result = RDAPClient().lookup_domain("example.com", ["example.com"], ["From"])
        self.assertTrue(result.no_record)

        self.assertEqual(
            prepare_domain_registration_targets({"sender": "from@example.com", "reply_to": "Not found"}),
            [{"registered_domain": "example.com", "observed_hostnames": ["example.com"], "source_labels": ["From"]}],
        )

    def test_from_and_reply_to_domains_are_deduplicated_without_losing_reply_to(self) -> None:
        different = prepare_domain_registration_targets(
            {"sender": "from@example.com", "reply_to": "reply@example.net"}
        )
        self.assertEqual(
            [item["registered_domain"] for item in different], ["example.com", "example.net"]
        )

        identical = prepare_domain_registration_targets(
            {"sender": "from@login.example.com", "reply_to": "reply@example.com"}
        )
        self.assertEqual(len(identical), 1)
        self.assertEqual(identical[0]["source_labels"], ["From", "Reply-To"])

    def test_exchange_style_from_address_reaches_domain_registration_targets(self) -> None:
        targets = prepare_domain_registration_targets(
            {"sender": "Example User [USER@UAB.EDU]", "reply_to": "Not found"}
        )
        self.assertEqual(
            targets,
            [{"registered_domain": "uab.edu", "observed_hostnames": ["uab.edu"], "source_labels": ["From"]}],
        )

    def test_first_domain_failure_does_not_prevent_reply_to_lookup(self) -> None:
        client = MagicMock()
        client.lookup_domain.side_effect = [
            RuntimeError("transient provider error"),
            DomainRegistrationResult(
                "example.net", ["example.net"], ["Reply-To"], "RDAP", "Lookup successful"
            ),
        ]
        service = ReputationService(rdap_client=client)

        result = service.check_domains(
            {"sender": "from@example.com", "reply_to": "reply@example.net"}
        )

        self.assertEqual(client.lookup_domain.call_count, 2)
        self.assertTrue(result.results[0].failed)
        self.assertEqual(result.results[1].registered_domain, "example.net")
        self.assertFalse(result.results[1].failed)

    def test_invalid_bootstrap_payload_does_not_poison_later_lookup(self) -> None:
        bootstrap = {"services": [[ ["com"], ["https://rdap.example/"] ]]}
        payload = {"events": []}
        invalid_response = MagicMock()
        invalid_response.read.return_value = b"{}"
        bootstrap_response = MagicMock()
        bootstrap_response.read.return_value = json.dumps(bootstrap).encode("utf-8")
        domain_response = MagicMock()
        domain_response.read.return_value = json.dumps(payload).encode("utf-8")
        with patch("reputation.rdap.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.side_effect = [
                invalid_response,
                bootstrap_response,
                domain_response,
            ]
            client = RDAPClient()
            first = client.lookup_domain("example.com", ["example.com"], ["From"])
            second = client.lookup_domain("example.com", ["example.com"], ["From"])

        self.assertTrue(first.failed)
        self.assertEqual(second.status, "Lookup successful")

    def test_html_domain_section_is_expanded_and_escaped(self) -> None:
        message = EmailMessage(); message.set_content("Body")
        summary = main.build_summary_data(message)
        summary["reputation_checks"] = {"sender_ip": {}, "url": {}, "attachment_hash": {}, "domain": {
            "provider": "RDAP", "status": "Domain Registration: Lookup successful", "total_unique_domains": 1,
            "total_checked_domains": 1, "total_found_domains": 1, "complete": True,
            "results": [{"registered_domain": "example.com", "observed_hostnames": ["x<script>.example.com"], "source_labels": ["URL", "From"], "registrar": "A very long Registrar", "registration_date": "2026-07-31T23:30:00-05:00", "domain_age": "10 days", "updated_date": "Not found", "expiration_date": "2027-08-02T00:00:00+00:00", "domain_status": ["clientDeleteProhibited", "clientTransferProhibited"], "nameservers": ["ns1.example.com", "ns2.example.com"], "status": "Lookup successful", "recently_registered": True}],
        }}
        report = main.build_html_report(summary)
        self.assertIn('<details class="collapsible reputation-details">\n<summary>Domain Registration</summary>', report)
        self.assertNotIn('<details class="collapsible reputation-details" open>', report)
        self.assertIn("<h3>Domain Information: example.com", report)
        self.assertIn("<th>Registered on</th><td><div class=\"domain-value\">07/31/2026</div>", report)
        self.assertIn("<th>Expires on</th><td><div class=\"domain-value\">08/02/2027</div>", report)
        self.assertNotIn("<th>Updated on</th>", report)
        self.assertIn("<th>Expires on</th>", report)
        self.assertIn("Recently registered", report)
        self.assertGreater(report.index("<th>Domain</th>"), report.index("<summary>Domain Registration</summary>"))
        self.assertLess(report.index("<th>Domain</th>"), report.index("<th>Registrar</th>"))
        self.assertNotIn("<th>Status</th>", report)
        self.assertNotIn("client delete prohibited", report)
        self.assertNotIn("<th>Observed hostnames</th>", report)
        self.assertNotIn("<th>Name servers</th>", report)
        self.assertNotIn("x&lt;script&gt;.example.com", report)

    def test_html_domain_country_codes_use_friendly_names(self) -> None:
        message = EmailMessage(); message.set_content("Body")
        summary = main.build_summary_data(message)
        summary["reputation_checks"] = {"sender_ip": {}, "url": {}, "attachment_hash": {}, "domain": {
            "provider": "RDAP", "status": "Domain Registration: Lookup successful", "total_unique_domains": 1,
            "total_checked_domains": 1, "total_found_domains": 1, "complete": True,
            "results": [{"registered_domain": "example.za", "source_labels": ["From"], "status": "Lookup successful", "registration_date": "Registration date unavailable", "country": "ZA"}],
        }}
        report = main.build_html_report(summary)
        self.assertIn(
            '<th>Country</th><td><div class="domain-value">South Africa</div>', report
        )


if __name__ == "__main__":
    unittest.main()
