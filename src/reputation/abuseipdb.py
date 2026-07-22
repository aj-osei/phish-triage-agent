"""AbuseIPDB sender-IP reputation provider."""

import ipaddress
import json
import os
import socket
from typing import Dict
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .models import ReputationResult


ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_TIMEOUT_SECONDS = 5


class AbuseIPDBClient:
    """Perform one safe AbuseIPDB IP check using an environment-provided key."""

    def __init__(self, api_key: str | None = None, timeout_seconds: int = ABUSEIPDB_TIMEOUT_SECONDS):
        self.api_key = api_key if api_key is not None else os.getenv("ABUSEIPDB_API_KEY", "")
        self.timeout_seconds = timeout_seconds

    def lookup_sender_ip(self, sender_ip: str) -> ReputationResult:
        """Return a normalized lookup result without raising provider errors."""
        if not self.api_key:
            return ReputationResult(
                category="Sender IP Reputation",
                provider="AbuseIPDB",
                status="Not checked — API key not configured",
            )

        try:
            ipaddress.ip_address(sender_ip)
        except ValueError:
            return ReputationResult(
                category="Sender IP Reputation",
                provider="AbuseIPDB",
                status="Not checked — sender IP unavailable",
            )

        request_url = ABUSEIPDB_CHECK_URL + "?" + urlencode(
            {"ipAddress": sender_ip, "maxAgeInDays": 90, "verbose": "true"}
        )
        request = Request(
            request_url,
            headers={
                "Accept": "application/json",
                "Key": self.api_key,
                "User-Agent": "Phish-Pharm/1.0",
            },
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (socket.timeout, TimeoutError):
            return self._failure("Lookup failed — request timed out")
        except HTTPError as error:
            if error.code == 429:
                return self._failure("Lookup failed — provider rate limit reached")
            return self._failure("Lookup failed — provider returned an error")
        except URLError as error:
            if isinstance(error.reason, (socket.timeout, TimeoutError)):
                return self._failure("Lookup failed — request timed out")
            return self._failure("Lookup failed — provider returned an error")
        except (UnicodeDecodeError, json.JSONDecodeError, OSError, ValueError):
            return self._failure("Lookup failed — provider returned malformed response")

        return self._normalize_response(sender_ip, payload)

    @staticmethod
    def _failure(status: str) -> ReputationResult:
        return ReputationResult(
            category="Sender IP Reputation",
            provider="AbuseIPDB",
            status=status,
        )

    def _normalize_response(self, sender_ip: str, payload: object) -> ReputationResult:
        """Validate and normalize the provider's documented check response."""
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
            return self._failure("Lookup failed — provider returned malformed response")

        data: Dict[str, object] = payload["data"]
        details = {
            "IP address": self._value(data.get("ipAddress"), sender_ip),
            "Abuse confidence score": self._value(data.get("abuseConfidenceScore")),
            "Total reports": self._value(data.get("totalReports")),
            "Country code": self._value(data.get("countryCode")),
            "ISP": self._value(data.get("isp")),
            "Domain": self._value(data.get("domain")),
            "Usage type": self._value(data.get("usageType")),
            "Last reported date": self._value(data.get("lastReportedAt")),
        }
        return ReputationResult(
            category="Sender IP Reputation",
            provider="AbuseIPDB",
            status="Lookup successful",
            details=details,
        )

    @staticmethod
    def _value(value: object, default: str = "Not found") -> str:
        """Normalize nullable provider fields for the report."""
        if value is None or value == "":
            return default
        return str(value)
