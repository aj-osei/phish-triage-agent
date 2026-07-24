"""Coordinator for provider-backed reputation checks."""

from typing import Dict, List
from urllib.parse import urlparse, urlunparse

from .abuseipdb import AbuseIPDBClient
from .models import ReputationResult, URLReputationItem, URLReputationSummary
from .virustotal import (
    VirusTotalURLClient,
    available_process_request_slots,
    record_process_request_attempt,
)


def build_unchecked_reputation_checks(sender_ip: str = "Not found") -> Dict[str, Dict[str, object]]:
    """Return report-safe placeholders when live lookups have not run."""
    sender_details = {"IP address": sender_ip} if sender_ip != "Not found" else {}
    return {
        "sender_ip": ReputationResult(
            category="Sender IP Reputation",
            provider="AbuseIPDB",
            status="Not checked - reputation lookup not run",
            details=sender_details,
        ).as_dict(),
        "domain": ReputationResult(
            category="Domain Reputation",
            provider="Not configured",
            status="Not checked yet - provider not configured",
        ).as_dict(),
        "url": URLReputationSummary(
            status="URL Reputation: Not checked - reputation lookup not run",
            total_extracted_urls=0,
            total_supported_urls=0,
            total_unique_urls=0,
        ).as_dict(),
        "attachment_hash": ReputationResult(
            category="Attachment Hash Reputation",
            provider="Not configured",
            status="Not checked yet - provider not configured",
        ).as_dict(),
    }


def normalize_supported_url(url: object) -> str | None:
    """Normalize HTTP(S) URLs for deterministic provider lookup de-duplication."""
    if not isinstance(url, str):
        return None
    candidate = url.strip()
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return urlunparse(parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()))


def prepare_url_reputation_targets(url_entries: object) -> tuple[int, int, List[Dict[str, str]]]:
    """Prefer decoded Safe Link targets and preserve first-seen display context."""
    if not isinstance(url_entries, list):
        return 0, 0, []

    supported_count = 0
    targets: List[Dict[str, str]] = []
    seen_urls = set()
    for entry in url_entries:
        if not isinstance(entry, dict):
            continue
        original_url = str(entry.get("original_url", ""))
        decoded_destination = str(entry.get("decoded_url", ""))
        lookup_candidate = decoded_destination or original_url
        normalized_url = normalize_supported_url(lookup_candidate)
        if not normalized_url:
            continue
        supported_count += 1
        if normalized_url in seen_urls:
            continue
        seen_urls.add(normalized_url)
        targets.append(
            {
                "original_url": original_url,
                "decoded_destination": decoded_destination,
                "lookup_url": normalized_url,
            }
        )
    return len(url_entries), supported_count, targets


class ReputationService:
    """Run report-time reputation checks without changing message parsing."""

    def __init__(
        self,
        abuseipdb_client: AbuseIPDBClient | None = None,
        virustotal_client: VirusTotalURLClient | None = None,
    ):
        self.abuseipdb_client = abuseipdb_client or AbuseIPDBClient()
        self.virustotal_client = virustotal_client or VirusTotalURLClient()
        self._sender_ip_cache: Dict[str, Dict[str, object]] = {}
        self._url_cache: Dict[str, URLReputationItem] = {}

    def check_email(self, summary: Dict[str, object]) -> Dict[str, Dict[str, object]]:
        """Run enabled providers and retain explicit future-provider placeholders."""
        sender_ip = str(summary.get("sender_ip", "Not found"))
        checks = build_unchecked_reputation_checks(sender_ip)
        checks["sender_ip"] = self.check_sender_ip(sender_ip)
        checks["url"] = self.check_urls(summary.get("url_entries", [])).as_dict()
        return checks

    def check_sender_ip(self, sender_ip: str) -> Dict[str, object]:
        """Avoid duplicate AbuseIPDB requests for the same IP in one service instance."""
        if sender_ip not in self._sender_ip_cache:
            self._sender_ip_cache[sender_ip] = self.abuseipdb_client.lookup_sender_ip(sender_ip).as_dict()
        return self._sender_ip_cache[sender_ip]

    def check_urls(self, url_entries: object) -> URLReputationSummary:
        """Check up to the available VirusTotal public-API budget for one report."""
        total_extracted, total_supported, targets = prepare_url_reputation_targets(url_entries)
        total_unique = len(targets)
        if total_extracted == 0:
            return URLReputationSummary(
                status="URL Reputation: No URLs found",
                total_extracted_urls=0,
                total_supported_urls=0,
                total_unique_urls=0,
                complete=True,
            )
        if total_supported == 0:
            return URLReputationSummary(
                status="URL Reputation: No supported HTTP or HTTPS URLs found",
                total_extracted_urls=total_extracted,
                total_supported_urls=0,
                total_unique_urls=0,
                complete=True,
            )
        if not self.virustotal_client.is_configured:
            return URLReputationSummary(
                status="URL Reputation: Not checked - API key not configured",
                total_extracted_urls=total_extracted,
                total_supported_urls=total_supported,
                total_unique_urls=total_unique,
                total_unchecked_urls=total_unique,
            )

        report_request_budget = min(4, available_process_request_slots())
        results: List[URLReputationItem] = []
        requests_attempted = 0
        terminal_result: URLReputationItem | None = None
        budget_exhausted = False

        for target in targets:
            lookup_url = target["lookup_url"]
            cached_result = self._url_cache.get(lookup_url)
            if cached_result is not None:
                results.append(cached_result)
                continue
            if requests_attempted >= report_request_budget:
                budget_exhausted = True
                break

            record_process_request_attempt()
            requests_attempted += 1
            item = self.virustotal_client.lookup_url(
                target["original_url"], target["lookup_url"], target["decoded_destination"]
            )
            self._url_cache[lookup_url] = item
            results.append(item)
            if item.stop_processing:
                terminal_result = item
                break

        checked_count = len(results)
        unchecked_count = max(0, total_unique - checked_count)
        successful_count = sum(1 for result in results if result.status == "Lookup successful")
        no_report_count = sum(1 for result in results if result.no_report)
        failed_count = sum(1 for result in results if result.failed)
        flagged_results = [result for result in results if result.flagged]
        rate_limit_reached = bool(terminal_result and terminal_result.rate_limited)
        partial = unchecked_count > 0 or failed_count > 0
        complete = not partial
        status = self._build_url_status(
            total_unique,
            checked_count,
            unchecked_count,
            successful_count,
            no_report_count,
            len(flagged_results),
            terminal_result,
            budget_exhausted,
        )
        return URLReputationSummary(
            status=status,
            total_extracted_urls=total_extracted,
            total_supported_urls=total_supported,
            total_unique_urls=total_unique,
            total_api_requests_attempted=requests_attempted,
            total_successfully_checked_urls=successful_count,
            total_no_report_urls=no_report_count,
            total_flagged_urls=len(flagged_results),
            total_failed_urls=failed_count,
            total_unchecked_urls=unchecked_count,
            complete=complete,
            partial=partial,
            rate_limit_reached=rate_limit_reached,
            flagged_results=flagged_results,
        )

    @staticmethod
    def _build_url_status(
        total_unique: int,
        checked_count: int,
        unchecked_count: int,
        successful_count: int,
        no_report_count: int,
        flagged_count: int,
        terminal_result: URLReputationItem | None,
        budget_exhausted: bool,
    ) -> str:
        """Describe only completed lookup coverage; never imply unchecked URLs are safe."""
        if terminal_result and terminal_result.authentication_failed and successful_count == 0 and no_report_count == 0:
            return "URL Reputation: Not checked - VirusTotal authentication failed"
        if no_report_count == checked_count and checked_count and not terminal_result:
            status = f"URL Reputation: VirusTotal had no existing report for {checked_count} checked URLs"
            if unchecked_count:
                status += f"; {unchecked_count} URLs were not checked"
            return status
        if flagged_count:
            if unchecked_count or terminal_result:
                status = (
                    "URL Reputation: Partially checked - "
                    f"{flagged_count} of {checked_count} checked URLs were flagged; "
                    f"{unchecked_count} of {total_unique} unique URLs were not checked"
                )
                if terminal_result and terminal_result.rate_limited:
                    status += "; VirusTotal rate limit reached"
                elif terminal_result:
                    status += "; results incomplete"
                return status
            return f"URL Reputation: {flagged_count} of {checked_count} checked URLs flagged by VirusTotal"
        if terminal_result:
            reason = terminal_result.status.replace("Lookup failed - ", "")
            return (
                "URL Reputation: Partially checked - "
                f"{reason} after {checked_count} of {total_unique} URLs; results incomplete"
            )
        if budget_exhausted or unchecked_count:
            return (
                f"URL Reputation: {checked_count} of {total_unique} unique URLs checked - "
                "none flagged in completed lookups; "
                f"{unchecked_count} URLs not checked because of the current VirusTotal request limit"
            )
        return (
            f"URL Reputation: {checked_count} unique URLs checked - "
            "none flagged by VirusTotal"
        )
