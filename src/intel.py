"""
Threat intelligence clients.

Four sources, each answering a different question:
  VirusTotal — what do ~70 AV engines say?
  GreyNoise  — is this IP indiscriminate internet background noise?
  OTX        — which published threat campaigns reference this?
  ThreatFox  — is this tied to a known malware family?

All four are queried concurrently and every failure is contained:
a source that errors or rate-limits returns an "unavailable" result
rather than aborting the lookup. A partial answer with its gaps
labelled is more useful than no answer.
"""

import asyncio
import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional

import httpx

from src import config

USER_AGENT = "alert-triage-engine/1.0 (portfolio project)"

# VirusTotal's free tier allows 4 requests per minute. This caps how
# many VT calls are in flight at once so one alert cannot burn the
# quota in a single burst. The other sources stay fully concurrent.
_VT_SEMAPHORE = asyncio.Semaphore(config.VT_MAX_CONCURRENT)


# ---------------------------------------------------------------
# Cache
# ---------------------------------------------------------------

def _cache_path(source: str, indicator: str) -> Path:
    """
    Cache filename derived from a hash of the indicator.

    Indicators contain characters illegal in filenames (slashes in
    URLs, colons), so the value is hashed rather than used directly.
    """
    digest = hashlib.sha256(indicator.encode()).hexdigest()[:16]
    return config.CACHE_DIR / f"{source}_{digest}.json"


def cache_get(source: str, indicator: str) -> Optional[dict[str, Any]]:
    """Return a cached result if present and still fresh."""
    path = _cache_path(source, indicator)
    if not path.exists():
        return None

    age_hours = (time.time() - path.stat().st_mtime) / 3600
    if age_hours > config.CACHE_MAX_AGE_HOURS:
        return None

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data["cached"] = True
        return data
    except (json.JSONDecodeError, OSError):
        return None


def cache_set(source: str, indicator: str, result: dict[str, Any]) -> None:
    """Store a result, ignoring failures — caching is best-effort."""
    try:
        config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(_cache_path(source, indicator), "w", encoding="utf-8") as f:
            json.dump(result, f)
    except OSError:
        pass


# ---------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------

def _result(source: str, available: bool, **fields: Any) -> dict[str, Any]:
    """
    Build a source result in a consistent shape.

    Every source returns the same envelope so the scoring stage does
    not need to know which source produced a given field, and an
    unavailable source stays distinguishable from a clean one.
    """
    return {"source": source, "available": available, "cached": False, **fields}


def _unavailable(source: str, reason: str) -> dict[str, Any]:
    return _result(source, available=False, reason=reason)


# ---------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------

VT_ENDPOINTS = {
    "ip": "ip_addresses",
    "domain": "domains",
    "url": "urls",
    "md5": "files",
    "sha1": "files",
    "sha256": "files",
}


async def query_virustotal(
    client: httpx.AsyncClient, indicator: str, ioc_type: str
) -> dict[str, Any]:
    """Look up an indicator's detection stats across VirusTotal's engines."""
    if not config.VIRUSTOTAL_API_KEY:
        return _unavailable("virustotal", "no API key configured")

    cached = cache_get("virustotal", indicator)
    if cached:
        return cached

    endpoint = VT_ENDPOINTS.get(ioc_type)
    if endpoint is None:
        return _unavailable("virustotal", f"unsupported type: {ioc_type}")

    # URLs are addressed by an unpadded base64 form of the URL itself.
    if ioc_type == "url":
        lookup = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
    else:
        lookup = indicator

    try:
        async with _VT_SEMAPHORE:
            response = await client.get(
                f"{config.VT_BASE_URL}/{endpoint}/{lookup}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY,
                         "User-Agent": USER_AGENT},
                timeout=config.REQUEST_TIMEOUT_SECONDS,
            )

        if response.status_code == 404:
            result = _result("virustotal", True, found=False,
                             malicious=0, suspicious=0, total=0,
                             detection_ratio="0/0")
            cache_set("virustotal", indicator, result)
            return result

        if response.status_code == 429:
            return _unavailable("virustotal", "rate limit exceeded")

        response.raise_for_status()
        stats = (response.json()
                 .get("data", {})
                 .get("attributes", {})
                 .get("last_analysis_stats", {}))

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 0

        result = _result(
            "virustotal", True,
            found=True,
            malicious=malicious,
            suspicious=suspicious,
            total=total,
            detection_ratio=f"{malicious}/{total}" if total else "0/0",
        )
        cache_set("virustotal", indicator, result)
        return result

    except httpx.TimeoutException:
        return _unavailable("virustotal", "request timed out")
    except httpx.HTTPStatusError as e:
        return _unavailable("virustotal", f"HTTP {e.response.status_code}")
    except httpx.HTTPError as e:
        return _unavailable("virustotal", f"request failed: {type(e).__name__}")
    except (KeyError, ValueError):
        return _unavailable("virustotal", "unexpected response format")


# ---------------------------------------------------------------
# GreyNoise
# ---------------------------------------------------------------

async def query_greynoise(
    client: httpx.AsyncClient, indicator: str, ioc_type: str
) -> dict[str, Any]:
    """
    Check whether an IP is indiscriminate internet-wide scanning.

    This is the source that reinterprets the others. An IP with many
    abuse reports that GreyNoise sees scanning everyone is background
    noise; the same reports on an IP GreyNoise has never observed
    means it came for this network specifically.
    """
    if ioc_type != "ip":
        return _unavailable("greynoise", "IP addresses only")

    if not config.GREYNOISE_API_KEY:
        return _unavailable("greynoise", "no API key configured")

    cached = cache_get("greynoise", indicator)
    if cached:
        return cached

    try:
        response = await client.get(
            f"{config.GREYNOISE_BASE_URL}/{indicator}",
            headers={"key": config.GREYNOISE_API_KEY,
                     "User-Agent": USER_AGENT},
            timeout=config.REQUEST_TIMEOUT_SECONDS,
        )

        # 404 means GreyNoise has never seen this IP scanning — which
        # is meaningful, not an error. It rules OUT the noise
        # explanation rather than telling us nothing.
        if response.status_code == 404:
            result = _result("greynoise", True, found=False, noise=False,
                             classification="not observed scanning")
            cache_set("greynoise", indicator, result)
            return result

        if response.status_code == 429:
            return _unavailable("greynoise", "rate limit exceeded")

        response.raise_for_status()
        data = response.json()

        result = _result(
            "greynoise", True,
            found=True,
            noise=data.get("noise", False),
            riot=data.get("riot", False),
            classification=data.get("classification", "unknown"),
            name=data.get("name", ""),
            last_seen=data.get("last_seen", ""),
        )
        cache_set("greynoise", indicator, result)
        return result

    except httpx.TimeoutException:
        return _unavailable("greynoise", "request timed out")
    except httpx.HTTPStatusError as e:
        return _unavailable("greynoise", f"HTTP {e.response.status_code}")
    except httpx.HTTPError as e:
        return _unavailable("greynoise", f"request failed: {type(e).__name__}")
    except (KeyError, ValueError):
        return _unavailable("greynoise", "unexpected response format")


# ---------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------

OTX_SECTIONS = {
    "ip": "IPv4",
    "domain": "domain",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}


async def query_otx(
    client: httpx.AsyncClient, indicator: str, ioc_type: str
) -> dict[str, Any]:
    """
    Find which published threat reports reference this indicator.

    OTX is organised around pulses — reports written by researchers.
    Naming the campaign an indicator belongs to is more useful in a
    case note than a numeric reputation score.
    """
    if not config.OTX_API_KEY:
        return _unavailable("otx", "no API key configured")

    cached = cache_get("otx", indicator)
    if cached:
        return cached

    section = OTX_SECTIONS.get(ioc_type)
    if section is None:
        return _unavailable("otx", f"unsupported type: {ioc_type}")

    try:
        response = await client.get(
            f"{config.OTX_BASE_URL}/{section}/{indicator}/general",
            headers={"X-OTX-API-KEY": config.OTX_API_KEY,
                     "User-Agent": USER_AGENT},
            timeout=config.REQUEST_TIMEOUT_SECONDS,
        )

        if response.status_code == 404:
            result = _result("otx", True, found=False, pulse_count=0,
                             pulses=[], tags=[])
            cache_set("otx", indicator, result)
            return result

        response.raise_for_status()
        data = response.json()
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        result = _result(
            "otx", True,
            found=bool(pulses),
            pulse_count=pulse_info.get("count", 0),
            pulses=[p.get("name", "")[:80] for p in pulses[:5]],
            tags=sorted({t for p in pulses for t in p.get("tags", [])})[:10],
        )
        cache_set("otx", indicator, result)
        return result

    except httpx.TimeoutException:
        return _unavailable("otx", "request timed out")
    except httpx.HTTPStatusError as e:
        return _unavailable("otx", f"HTTP {e.response.status_code}")
    except httpx.HTTPError as e:
        return _unavailable("otx", f"request failed: {type(e).__name__}")
    except (KeyError, ValueError):
        return _unavailable("otx", "unexpected response format")


# ---------------------------------------------------------------
# ThreatFox (abuse.ch)
# ---------------------------------------------------------------

async def query_threatfox(
    client: httpx.AsyncClient, indicator: str, ioc_type: str
) -> dict[str, Any]:
    """
    Check abuse.ch's IOC database for malware family association.

    abuse.ch moved their APIs behind authentication in 2025; the key
    is still free but now required.
    """
    if not config.ABUSECH_API_KEY:
        return _unavailable("threatfox", "no API key configured")

    cached = cache_get("threatfox", indicator)
    if cached:
        return cached

    try:
        response = await client.post(
            config.THREATFOX_URL,
            json={"query": "search_ioc", "search_term": indicator},
            headers={"User-Agent": USER_AGENT,
                     "Auth-Key": config.ABUSECH_API_KEY},
            timeout=config.REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") != "ok" or not data.get("data"):
            result = _result("threatfox", True, found=False,
                             malware_families=[], threat_types=[])
            cache_set("threatfox", indicator, result)
            return result

        entries = data["data"]
        result = _result(
            "threatfox", True,
            found=True,
            malware_families=sorted({
                e.get("malware_printable", "") for e in entries
                if e.get("malware_printable")
            })[:5],
            threat_types=sorted({
                e.get("threat_type", "") for e in entries
                if e.get("threat_type")
            }),
            confidence=max((e.get("confidence_level", 0) for e in entries),
                           default=0),
        )
        cache_set("threatfox", indicator, result)
        return result

    except httpx.TimeoutException:
        return _unavailable("threatfox", "request timed out")
    except httpx.HTTPStatusError as e:
        return _unavailable("threatfox", f"HTTP {e.response.status_code}")
    except httpx.HTTPError as e:
        return _unavailable("threatfox", f"request failed: {type(e).__name__}")
    except (KeyError, ValueError):
        return _unavailable("threatfox", "unexpected response format")


# ---------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------

async def enrich_indicator(
    client: httpx.AsyncClient, ioc: dict[str, Any]
) -> dict[str, Any]:
    """Query every source for one indicator, concurrently."""
    value, ioc_type = ioc["value"], ioc["type"]

    results = await asyncio.gather(
        query_virustotal(client, value, ioc_type),
        query_greynoise(client, value, ioc_type),
        query_otx(client, value, ioc_type),
        query_threatfox(client, value, ioc_type),
        return_exceptions=True,
    )

    sources: dict[str, Any] = {}
    for item in results:
        # A source that raised despite its own error handling must not
        # take down the whole lookup.
        if isinstance(item, BaseException):
            continue
        sources[item["source"]] = item

    enriched = dict(ioc)
    enriched["sources"] = sources
    return enriched


async def enrich_all(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Enrich every enrichable indicator, all concurrently.

    Indicators marked non-enrichable (private addresses, emails) pass
    through untouched — they remain useful context for the analyst
    even though no external intelligence exists for them.
    """
    to_enrich = [i for i in iocs if i.get("enrichable")]
    passthrough = [dict(i, sources={}) for i in iocs if not i.get("enrichable")]

    if not to_enrich:
        return passthrough

    async with httpx.AsyncClient() as client:
        enriched = await asyncio.gather(
            *(enrich_indicator(client, ioc) for ioc in to_enrich)
        )

    return list(enriched) + passthrough