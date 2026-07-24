"""Normalized result models shared by reputation providers."""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class ReputationResult:
    """One provider result formatted for safe report rendering."""

    category: str
    provider: str
    status: str
    details: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        """Return a plain dictionary used by the report renderer."""
        return {
            "category": self.category,
            "provider": self.provider,
            "status": self.status,
            "details": self.details,
        }


@dataclass
class URLReputationItem:
    """One normalized VirusTotal URL report result."""

    original_url: str
    lookup_url: str
    decoded_destination: str
    provider: str
    status: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    total_engines: int = 0
    last_analysis_date: str = "Not found"
    report_id: str = "Not found"
    no_report: bool = False
    failed: bool = False
    stop_processing: bool = False
    rate_limited: bool = False
    authentication_failed: bool = False

    @property
    def flagged(self) -> bool:
        """Return True only when VirusTotal vendors report a detection."""
        return self.malicious > 0 or self.suspicious > 0

    def as_dict(self) -> Dict[str, object]:
        """Return safe, report-ready fields without raw provider JSON."""
        return {
            "original_url": self.original_url,
            "lookup_url": self.lookup_url,
            "decoded_destination": self.decoded_destination,
            "provider": self.provider,
            "status": self.status,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "timeout": self.timeout,
            "total_engines": self.total_engines,
            "last_analysis_date": self.last_analysis_date,
            "report_id": self.report_id,
            "no_report": self.no_report,
            "failed": self.failed,
            "stop_processing": self.stop_processing,
            "rate_limited": self.rate_limited,
            "authentication_failed": self.authentication_failed,
            "flagged": self.flagged,
        }


@dataclass
class URLReputationSummary:
    """Overall bounded URL-reputation state for one report."""

    status: str
    total_extracted_urls: int
    total_supported_urls: int
    total_unique_urls: int
    total_api_requests_attempted: int = 0
    total_successfully_checked_urls: int = 0
    total_no_report_urls: int = 0
    total_flagged_urls: int = 0
    total_failed_urls: int = 0
    total_unchecked_urls: int = 0
    complete: bool = False
    partial: bool = False
    rate_limit_reached: bool = False
    flagged_results: List[URLReputationItem] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        """Return report-ready aggregate data and only flagged item details."""
        return {
            "category": "URL Reputation",
            "provider": "VirusTotal",
            "status": self.status,
            "total_extracted_urls": self.total_extracted_urls,
            "total_supported_urls": self.total_supported_urls,
            "total_unique_urls": self.total_unique_urls,
            "total_api_requests_attempted": self.total_api_requests_attempted,
            "total_successfully_checked_urls": self.total_successfully_checked_urls,
            "total_no_report_urls": self.total_no_report_urls,
            "total_flagged_urls": self.total_flagged_urls,
            "total_failed_urls": self.total_failed_urls,
            "total_unchecked_urls": self.total_unchecked_urls,
            "complete": self.complete,
            "partial": self.partial,
            "rate_limit_reached": self.rate_limit_reached,
            "flagged_results": [result.as_dict() for result in self.flagged_results],
        }
