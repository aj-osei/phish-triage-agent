"""VirusTotal v3 URL reputation provider and process-local request budget."""

import base64
from collections import deque
from datetime import datetime, timezone
import json
import os
import socket
import time
from typing import Deque
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import URLReputationItem


VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3/urls/"
VIRUSTOTAL_TIMEOUT_SECONDS = 5
VIRUSTOTAL_MAX_REQUESTS_PER_REPORT = 4
VIRUSTOTAL_REQUEST_WINDOW_SECONDS = 60
_REQUEST_TIMESTAMPS: Deque[float] = deque()


def build_virustotal_url_id(url: str) -> str:
    """Build the documented URL-safe Base64 VirusTotal URL identifier."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def available_process_request_slots(now: float | None = None) -> int:
    """Return remaining local public-API slots in the rolling 60-second window."""
    current_time = time.time() if now is None else now
    while _REQUEST_TIMESTAMPS and current_time - _REQUEST_TIMESTAMPS[0] >= VIRUSTOTAL_REQUEST_WINDOW_SECONDS:
        _REQUEST_TIMESTAMPS.popleft()
    return max(0, VIRUSTOTAL_MAX_REQUESTS_PER_REPORT - len(_REQUEST_TIMESTAMPS))


def record_process_request_attempt(now: float | None = None) -> None:
    """Record one attempted VirusTotal request without persisting state to disk."""
    current_time = time.time() if now is None else now
    available_process_request_slots(current_time)
    _REQUEST_TIMESTAMPS.append(current_time)


class VirusTotalURLClient:
    """Retrieve existing VirusTotal URL reports without submitting URLs."""

    def __init__(self, api_key: str | None = None, timeout_seconds: int = VIRUSTOTAL_TIMEOUT_SECONDS):
        self.api_key = api_key if api_key is not None else os.getenv("VIRUSTOTAL_API_KEY", "")
        self.timeout_seconds = timeout_seconds

    @property
    def is_configured(self) -> bool:
        """Return True only when an API key is available for a report lookup."""
        return bool(self.api_key)

    def lookup_url(
        self, original_url: str, lookup_url: str, decoded_destination: str = ""
    ) -> URLReputationItem:
        """Retrieve one existing report and normalize expected error conditions."""
        if not self.api_key:
            return self._failure(
                original_url,
                lookup_url,
                decoded_destination,
                "Not checked - API key not configured",
            )

        request = Request(
            VIRUSTOTAL_URL_API + build_virustotal_url_id(lookup_url),
            headers={
                "Accept": "application/json",
                "x-apikey": self.api_key,
                "User-Agent": "Phish-Pharm/1.0",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            if error.code == 404:
                return URLReputationItem(
                    original_url=original_url,
                    lookup_url=lookup_url,
                    decoded_destination=decoded_destination,
                    provider="VirusTotal",
                    status="No existing VirusTotal report found",
                    no_report=True,
                )
            if error.code in (401, 403):
                return self._failure(
                    original_url,
                    lookup_url,
                    decoded_destination,
                    "Lookup failed - VirusTotal authentication failed",
                    stop_processing=True,
                    authentication_failed=True,
                )
            if error.code == 429:
                return self._failure(
                    original_url,
                    lookup_url,
                    decoded_destination,
                    "Lookup failed - VirusTotal rate limit reached",
                    stop_processing=True,
                    rate_limited=True,
                )
            return self._failure(
                original_url,
                lookup_url,
                decoded_destination,
                "Lookup failed - provider returned an error",
                stop_processing=True,
            )
        except (socket.timeout, TimeoutError):
            return self._failure(
                original_url,
                lookup_url,
                decoded_destination,
                "Lookup failed - request timed out",
                stop_processing=True,
            )
        except URLError as error:
            status = (
                "Lookup failed - request timed out"
                if isinstance(error.reason, (socket.timeout, TimeoutError))
                else "Lookup failed - network unavailable"
            )
            return self._failure(
                original_url, lookup_url, decoded_destination, status, stop_processing=True
            )
        except (UnicodeDecodeError, json.JSONDecodeError, OSError, ValueError):
            return self._failure(
                original_url,
                lookup_url,
                decoded_destination,
                "Lookup failed - provider returned malformed response",
                stop_processing=True,
            )

        return self._normalize_response(original_url, lookup_url, decoded_destination, payload)

    @staticmethod
    def _failure(
        original_url: str,
        lookup_url: str,
        decoded_destination: str,
        status: str,
        stop_processing: bool = False,
        rate_limited: bool = False,
        authentication_failed: bool = False,
    ) -> URLReputationItem:
        return URLReputationItem(
            original_url=original_url,
            lookup_url=lookup_url,
            decoded_destination=decoded_destination,
            provider="VirusTotal",
            status=status,
            failed=True,
            stop_processing=stop_processing,
            rate_limited=rate_limited,
            authentication_failed=authentication_failed,
        )

    def _normalize_response(
        self, original_url: str, lookup_url: str, decoded_destination: str, payload: object
    ) -> URLReputationItem:
        """Validate the v3 response and retain only useful normalized fields."""
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
            return self._failure(
                original_url,
                lookup_url,
                decoded_destination,
                "Lookup failed - provider returned malformed response",
                stop_processing=True,
            )
        data = payload["data"]
        attributes = data.get("attributes")
        if not isinstance(attributes, dict) or not isinstance(attributes.get("last_analysis_stats"), dict):
            return self._failure(
                original_url,
                lookup_url,
                decoded_destination,
                "Lookup failed - provider returned malformed response",
                stop_processing=True,
            )

        statistics = attributes["last_analysis_stats"]
        numeric_statistics = {
            str(name): value
            for name, value in statistics.items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
        last_analysis_value = attributes.get("last_analysis_date")
        return URLReputationItem(
            original_url=original_url,
            lookup_url=lookup_url,
            decoded_destination=decoded_destination,
            provider="VirusTotal",
            status="Lookup successful",
            malicious=self._statistic(numeric_statistics, "malicious"),
            suspicious=self._statistic(numeric_statistics, "suspicious"),
            harmless=self._statistic(numeric_statistics, "harmless"),
            undetected=self._statistic(numeric_statistics, "undetected"),
            timeout=self._statistic(numeric_statistics, "timeout"),
            total_engines=sum(numeric_statistics.values()),
            last_analysis_date=self._format_analysis_date(last_analysis_value),
            report_id=str(data.get("id") or "Not found"),
        )

    @staticmethod
    def _statistic(statistics: dict[str, int], name: str) -> int:
        value = statistics.get(name, 0)
        return value if value >= 0 else 0

    @staticmethod
    def _format_analysis_date(value: object) -> str:
        if not isinstance(value, (int, float)):
            return "Not found"
        try:
            return datetime.fromtimestamp(value, timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return "Not found"
