"""Coordinator for provider-backed and future reputation categories."""

from typing import Dict

from .abuseipdb import AbuseIPDBClient
from .models import ReputationResult


FUTURE_CATEGORIES = (
    "Domain Reputation",
    "URL Reputation",
    "Attachment Hash Reputation",
)


def build_unchecked_reputation_checks(sender_ip: str = "Not found") -> Dict[str, Dict[str, object]]:
    """Return report-safe placeholders when a live lookup has not run."""
    sender_details = {"IP address": sender_ip} if sender_ip != "Not found" else {}
    checks = {
        "sender_ip": ReputationResult(
            category="Sender IP Reputation",
            provider="AbuseIPDB",
            status="Not checked — reputation lookup not run",
            details=sender_details,
        ).as_dict()
    }
    for category in FUTURE_CATEGORIES:
        checks[category.lower().replace(" ", "_").replace("_reputation", "")] = ReputationResult(
            category=category,
            provider="Not configured",
            status="Not checked yet — provider not configured",
        ).as_dict()
    return checks


class ReputationService:
    """Run report-time reputation checks without changing message parsing."""

    def __init__(self, abuseipdb_client: AbuseIPDBClient | None = None):
        self.abuseipdb_client = abuseipdb_client or AbuseIPDBClient()
        self._sender_ip_cache: Dict[str, Dict[str, object]] = {}

    def check_email(self, summary: Dict[str, object]) -> Dict[str, Dict[str, object]]:
        """Check only the sender IP today and retain future category placeholders."""
        sender_ip = str(summary.get("sender_ip", "Not found"))
        checks = build_unchecked_reputation_checks(sender_ip)
        checks["sender_ip"] = self.check_sender_ip(sender_ip)
        return checks

    def check_sender_ip(self, sender_ip: str) -> Dict[str, object]:
        """Avoid duplicate provider requests for the same IP in one service instance."""
        if sender_ip not in self._sender_ip_cache:
            self._sender_ip_cache[sender_ip] = self.abuseipdb_client.lookup_sender_ip(sender_ip).as_dict()
        return self._sender_ip_cache[sender_ip]
