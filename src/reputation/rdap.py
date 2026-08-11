"""RDAP domain-registration lookups using IANA bootstrap discovery."""

from datetime import datetime, timezone
import ipaddress
import json
import socket
from typing import Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import tldextract

from .models import DomainRegistrationResult


IANA_DNS_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_TIMEOUT_SECONDS = 5
_BOOTSTRAP_CACHE: Dict[str, object] | None = None
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def normalize_registered_domain(hostname: object) -> tuple[str, str] | None:
    """Return normalized observed hostname and PSL-based registered domain."""
    if not isinstance(hostname, str):
        return None
    candidate = hostname.strip().rstrip(".").lower()
    if not candidate or candidate == "localhost":
        return None
    try:
        candidate = candidate.encode("idna").decode("ascii")
        ipaddress.ip_address(candidate.strip("[]"))
        return None
    except ValueError:
        pass
    except UnicodeError:
        return None
    extracted = _EXTRACT(candidate)
    registered = extracted.top_domain_under_public_suffix.lower()
    if not extracted.suffix or not registered or "." not in registered:
        return None
    return candidate, registered


class RDAPClient:
    """Retrieve RDAP registration context without visiting a represented domain."""

    def __init__(self, timeout_seconds: int = RDAP_TIMEOUT_SECONDS):
        self.timeout_seconds = timeout_seconds

    def lookup_domain(
        self, registered_domain: str, observed_hostnames: list[str], source_labels: list[str]
    ) -> DomainRegistrationResult:
        base_url = self._lookup_base_url(registered_domain)
        if not base_url:
            return self._failure(registered_domain, observed_hostnames, source_labels, "Lookup failed - IANA bootstrap unavailable")
        request = Request(base_url.rstrip("/") + "/domain/" + registered_domain, headers={"Accept": "application/rdap+json, application/json", "User-Agent": "Phish-Pharm/1.0"})
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            if error.code == 404:
                return DomainRegistrationResult(registered_domain, observed_hostnames, source_labels, "RDAP", "No registration record returned", no_record=True)
            return self._failure(registered_domain, observed_hostnames, source_labels, "Lookup failed - RDAP provider unavailable")
        except (socket.timeout, TimeoutError):
            return self._failure(registered_domain, observed_hostnames, source_labels, "Lookup failed - request timed out")
        except URLError:
            return self._failure(registered_domain, observed_hostnames, source_labels, "Lookup failed - network unavailable")
        except (UnicodeDecodeError, json.JSONDecodeError, OSError, ValueError):
            return self._failure(registered_domain, observed_hostnames, source_labels, "Lookup failed - malformed RDAP response")
        try:
            return self._normalize(registered_domain, observed_hostnames, source_labels, payload)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            return self._failure(
                registered_domain,
                observed_hostnames,
                source_labels,
                "Lookup failed - malformed RDAP response",
            )

    def _lookup_base_url(self, domain: str) -> str:
        global _BOOTSTRAP_CACHE
        try:
            if _BOOTSTRAP_CACHE is None:
                request = Request(IANA_DNS_BOOTSTRAP_URL, headers={"Accept": "application/json", "User-Agent": "Phish-Pharm/1.0"})
                with urlopen(request, timeout=self.timeout_seconds) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                services = payload.get("services") if isinstance(payload, dict) else None
                if not isinstance(services, list):
                    return ""
                # Cache only a structurally valid response. A transient bad response must not
                # poison subsequent domain lookups in the same report run.
                _BOOTSTRAP_CACHE = payload
            tld = domain.rsplit(".", 1)[-1]
            for service in _BOOTSTRAP_CACHE.get("services", []):
                if not isinstance(service, list) or len(service) != 2 or tld not in service[0] or not service[1]:
                    continue
                base_url = str(service[1][0])
                return base_url if base_url.startswith("https://") else ""
        except (HTTPError, URLError, socket.timeout, TimeoutError, UnicodeDecodeError, json.JSONDecodeError, OSError, ValueError, AttributeError):
            return ""
        return ""

    @staticmethod
    def _failure(domain: str, hostnames: list[str], labels: list[str], status: str) -> DomainRegistrationResult:
        return DomainRegistrationResult(domain, hostnames, labels, "RDAP", status, failed=True)

    def _normalize(self, domain: str, hostnames: list[str], labels: list[str], payload: object) -> DomainRegistrationResult:
        if not isinstance(payload, dict):
            return self._failure(domain, hostnames, labels, "Lookup failed - malformed RDAP response")
        events = payload.get("events", [])
        dates = {"registration": None, "last changed": None, "expiration": None}
        if isinstance(events, list):
            for event in events:
                if isinstance(event, dict) and isinstance(event.get("eventAction"), str):
                    key = event["eventAction"].lower()
                    if key in dates and isinstance(event.get("eventDate"), str): dates[key] = event["eventDate"]
        registered_at = self._parse_date(dates["registration"])
        if registered_at and registered_at.tzinfo is None:
            registered_at = registered_at.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - registered_at).days if registered_at else None
        nameservers = [str(item.get("ldhName") or item.get("unicodeName")) for item in payload.get("nameservers", []) if isinstance(item, dict) and (item.get("ldhName") or item.get("unicodeName"))]
        statuses = [str(value) for value in payload.get("status", []) if isinstance(value, str)]
        registrar = "Not found"
        country = "Not found"
        for entity in payload.get("entities", []):
            if not isinstance(entity, dict):
                continue
            if "registrar" in entity.get("roles", []):
                registrar = self._entity_name(entity)
            country = country if country != "Not found" else self._entity_country(entity)
        return DomainRegistrationResult(
            domain, hostnames, labels, "RDAP", "Lookup successful", registrar=registrar,
            registration_date=dates["registration"] or "Registration date unavailable",
            updated_date=dates["last changed"] or "Not found", expiration_date=dates["expiration"] or "Not found",
            domain_age=(f"{age_days} days" if age_days is not None else "Not calculated"),
            recently_registered=age_days is not None and age_days <= 30,
            domain_status=statuses, nameservers=nameservers, country=country, handle=str(payload.get("handle") or "Not found"),
        )

    @staticmethod
    def _entity_name(entity: dict) -> str:
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for value in vcard[1]:
                if isinstance(value, list) and value and value[0] in {"fn", "org"} and len(value) > 3:
                    return str(value[3])
        return "Not found"

    @staticmethod
    def _entity_country(entity: dict) -> str:
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for value in vcard[1]:
                if isinstance(value, list) and value and value[0] == "country-name" and len(value) > 3:
                    return str(value[3])
        return "Not found"

    @staticmethod
    def _parse_date(value: object) -> datetime | None:
        if not isinstance(value, str): return None
        try: return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError: return None
