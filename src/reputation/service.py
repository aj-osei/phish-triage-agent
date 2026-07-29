"""Coordinator for provider-backed reputation checks."""

import re
from typing import Dict, List
from urllib.parse import urlparse, urlunparse

from .abuseipdb import AbuseIPDBClient
from .models import (
    AttachmentReputationItem,
    AttachmentReputationSummary,
    ReputationResult,
    URLReputationItem,
    URLReputationSummary,
)
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
        "attachment_hash": AttachmentReputationSummary(
            status="Attachment Hash Reputation: Not checked - reputation lookup not run",
            total_normal_attachments=0,
            total_unique_hashes=0,
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


SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def prepare_attachment_reputation_targets(
    attachments: object,
) -> tuple[int, List[Dict[str, object]]]:
    """Select non-empty normal attachments and de-duplicate their valid SHA-256 hashes."""
    if not isinstance(attachments, list):
        return 0, []

    targets_by_hash: Dict[str, Dict[str, object]] = {}
    for attachment in attachments:
        if not isinstance(attachment, dict):
            continue
        sha256 = str(attachment.get("sha256", "")).lower()
        size_bytes = attachment.get("size_bytes", 0)
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0:
            continue
        if not SHA256_PATTERN.fullmatch(sha256):
            continue
        target = targets_by_hash.setdefault(
            sha256,
            {
                "sha256": sha256,
                "filenames": [],
                "content_types": [],
                "sizes_bytes": [],
            },
        )
        filename = str(attachment.get("filename", "Not found"))
        content_type = str(attachment.get("content_type", "application/octet-stream"))
        if filename not in target["filenames"]:
            target["filenames"].append(filename)
        if content_type not in target["content_types"]:
            target["content_types"].append(content_type)
        target["sizes_bytes"].append(size_bytes)
    return len(attachments), list(targets_by_hash.values())


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
        self._attachment_cache: Dict[str, AttachmentReputationItem] = {}

    def check_email(self, summary: Dict[str, object]) -> Dict[str, Dict[str, object]]:
        """Run enabled providers and retain explicit future-provider placeholders."""
        sender_ip = str(summary.get("sender_ip", "Not found"))
        checks = build_unchecked_reputation_checks(sender_ip)
        checks["sender_ip"] = self.check_sender_ip(sender_ip)
        url_result, attachment_result = self._check_shared_virustotal_indicators(
            summary.get("url_entries", []),
            summary.get("attachments", []),
            summary.get("inline_content", []),
        )
        checks["url"] = url_result.as_dict()
        checks["attachment_hash"] = attachment_result.as_dict()
        return checks

    def check_sender_ip(self, sender_ip: str) -> Dict[str, object]:
        """Avoid duplicate AbuseIPDB requests for the same IP in one service instance."""
        if sender_ip not in self._sender_ip_cache:
            self._sender_ip_cache[sender_ip] = self.abuseipdb_client.lookup_sender_ip(sender_ip).as_dict()
        return self._sender_ip_cache[sender_ip]

    def check_attachments(
        self, attachments: object, inline_content: object = None
    ) -> AttachmentReputationSummary:
        """Check attachment hashes alone while retaining the provider-wide rolling budget."""
        _, result = self._check_shared_virustotal_indicators([], attachments, inline_content)
        return result

    def _check_shared_virustotal_indicators(
        self, url_entries: object, attachments: object, inline_content: object
    ) -> tuple[URLReputationSummary, AttachmentReputationSummary]:
        """Alternate file-hash and URL lookups under one local VirusTotal request budget."""
        total_extracted, total_supported, url_targets = prepare_url_reputation_targets(url_entries)
        total_normal_attachments, attachment_targets = prepare_attachment_reputation_targets(attachments)
        total_urls = len(url_targets)
        total_hashes = len(attachment_targets)
        inline_present = isinstance(inline_content, list) and bool(inline_content)

        if not self.virustotal_client.is_configured:
            return (
                self._url_summary_without_lookup(total_extracted, total_supported, total_urls),
                self._attachment_summary_without_lookup(
                    total_normal_attachments, total_hashes, inline_present
                ),
            )

        url_results: List[URLReputationItem] = []
        attachment_results: List[AttachmentReputationItem] = []
        url_queue = list(url_targets)
        attachment_queue = list(attachment_targets)
        requests_attempted = 0
        budget = min(4, available_process_request_slots())
        terminal_result: object | None = None
        next_kind = "attachment"

        while (url_queue or attachment_queue) and requests_attempted < budget and terminal_result is None:
            if next_kind == "attachment" and attachment_queue:
                kind, target = "attachment", attachment_queue.pop(0)
            elif next_kind == "url" and url_queue:
                kind, target = "url", url_queue.pop(0)
            elif attachment_queue:
                kind, target = "attachment", attachment_queue.pop(0)
            else:
                kind, target = "url", url_queue.pop(0)
            next_kind = "url" if kind == "attachment" else "attachment"

            if kind == "attachment":
                sha256 = str(target["sha256"])
                item = self._attachment_cache.get(sha256)
                if item is None:
                    record_process_request_attempt()
                    requests_attempted += 1
                    item = self.virustotal_client.lookup_file_hash(
                        sha256,
                        list(target["filenames"]),
                        list(target["content_types"]),
                        list(target["sizes_bytes"]),
                    )
                    self._attachment_cache[sha256] = item
                attachment_results.append(item)
            else:
                lookup_url = str(target["lookup_url"])
                item = self._url_cache.get(lookup_url)
                if item is None:
                    record_process_request_attempt()
                    requests_attempted += 1
                    item = self.virustotal_client.lookup_url(
                        str(target["original_url"]), lookup_url, str(target["decoded_destination"])
                    )
                    self._url_cache[lookup_url] = item
                url_results.append(item)

            if item.stop_processing:
                terminal_result = item

        budget_exhausted = bool(url_queue or attachment_queue) and terminal_result is None
        return (
            self._summarize_urls(
                total_extracted, total_supported, total_urls, url_results, requests_attempted,
                terminal_result, budget_exhausted,
            ),
            self._summarize_attachments(
                total_normal_attachments, total_hashes, attachment_results, requests_attempted,
                terminal_result, budget_exhausted, inline_present,
            ),
        )

    def _url_summary_without_lookup(
        self, total_extracted: int, total_supported: int, total_urls: int
    ) -> URLReputationSummary:
        if total_extracted == 0:
            return URLReputationSummary("URL Reputation: No URLs found", 0, 0, 0, complete=True)
        if total_supported == 0:
            return URLReputationSummary(
                "URL Reputation: No supported HTTP or HTTPS URLs found",
                total_extracted, 0, 0, complete=True,
            )
        return URLReputationSummary(
            "URL Reputation: Not checked - API key not configured",
            total_extracted, total_supported, total_urls, total_unchecked_urls=total_urls,
        )

    def _attachment_summary_without_lookup(
        self, total_normal: int, total_hashes: int, inline_present: bool
    ) -> AttachmentReputationSummary:
        if total_normal == 0:
            return AttachmentReputationSummary(
                "Attachment Hash Reputation: Not checked - no file attachments found",
                0, 0, complete=True, inline_content_present=inline_present,
            )
        if total_hashes == 0:
            return AttachmentReputationSummary(
                "Attachment Hash Reputation: Not checked - valid attachment hashes unavailable",
                total_normal, 0, complete=True, inline_content_present=inline_present,
            )
        return AttachmentReputationSummary(
            "Attachment Hash Reputation: Not checked - API key not configured",
            total_normal, total_hashes, total_unchecked_hashes=total_hashes,
            inline_content_present=inline_present,
        )

    def _summarize_urls(
        self, total_extracted: int, total_supported: int, total_urls: int,
        results: List[URLReputationItem], requests_attempted: int,
        terminal_result: object | None, budget_exhausted: bool,
    ) -> URLReputationSummary:
        if total_extracted == 0 or total_supported == 0:
            return self._url_summary_without_lookup(total_extracted, total_supported, total_urls)
        checked = len(results)
        successful = sum(item.status == "Lookup successful" for item in results)
        no_report = sum(item.no_report for item in results)
        failed = sum(item.failed for item in results)
        flagged = [item for item in results if item.flagged]
        unchecked = max(0, total_urls - checked)
        partial = bool(unchecked or failed)
        return URLReputationSummary(
            status=self._build_url_status(
                total_urls, checked, unchecked, successful, no_report, len(flagged), terminal_result, budget_exhausted
            ),
            total_extracted_urls=total_extracted,
            total_supported_urls=total_supported,
            total_unique_urls=total_urls,
            total_api_requests_attempted=requests_attempted,
            total_successfully_checked_urls=successful,
            total_no_report_urls=no_report,
            total_flagged_urls=len(flagged),
            total_failed_urls=failed,
            total_unchecked_urls=unchecked,
            complete=not partial,
            partial=partial,
            rate_limit_reached=bool(terminal_result and getattr(terminal_result, "rate_limited", False)),
            flagged_results=flagged,
        )

    def _summarize_attachments(
        self, total_normal: int, total_hashes: int, results: List[AttachmentReputationItem],
        requests_attempted: int, terminal_result: object | None, budget_exhausted: bool,
        inline_present: bool,
    ) -> AttachmentReputationSummary:
        if total_normal == 0 or total_hashes == 0:
            return self._attachment_summary_without_lookup(total_normal, total_hashes, inline_present)
        checked = len(results)
        successful = sum(item.status == "Lookup successful" for item in results)
        no_report = sum(item.no_report for item in results)
        failed = sum(item.failed for item in results)
        flagged = [item for item in results if item.flagged]
        unchecked = max(0, total_hashes - checked)
        partial = bool(unchecked or failed)
        return AttachmentReputationSummary(
            status=self._build_attachment_status(
                total_hashes, checked, unchecked, successful, no_report, len(flagged), terminal_result, budget_exhausted
            ),
            total_normal_attachments=total_normal,
            total_unique_hashes=total_hashes,
            total_api_requests_attempted=requests_attempted,
            total_successfully_checked_hashes=successful,
            total_no_report_hashes=no_report,
            total_flagged_hashes=len(flagged),
            total_failed_hashes=failed,
            total_unchecked_hashes=unchecked,
            complete=not partial,
            partial=partial,
            rate_limit_reached=bool(terminal_result and getattr(terminal_result, "rate_limited", False)),
            inline_content_present=inline_present,
            flagged_results=flagged,
        )

    @staticmethod
    def _build_attachment_status(
        total_hashes: int, checked: int, unchecked: int, successful: int, no_report: int,
        flagged: int, terminal_result: object | None, budget_exhausted: bool,
    ) -> str:
        if terminal_result and getattr(terminal_result, "authentication_failed", False) and not (successful or no_report):
            return "Attachment Hash Reputation: Not checked - VirusTotal authentication failed"
        if no_report == checked and checked and not terminal_result:
            return f"Attachment Hash Reputation: VirusTotal had no existing report for {checked} checked hashes"
        if flagged and not (unchecked or terminal_result):
            return f"Attachment Hash Reputation: {flagged} of {checked} checked hashes flagged by VirusTotal"
        if terminal_result:
            reason = str(getattr(terminal_result, "status", "provider unavailable")).replace("Lookup failed - ", "")
            return f"Attachment Hash Reputation: Partially checked - {reason} after {checked} of {total_hashes} hashes"
        if budget_exhausted or unchecked:
            return (
                f"Attachment Hash Reputation: {checked} of {total_hashes} attachment hashes checked - "
                "none flagged in completed lookups; remaining hashes not checked because of the shared VirusTotal request limit"
            )
        return f"Attachment Hash Reputation: {checked} attachment hashes checked - none flagged by VirusTotal"

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
