"""
Extraction stage: find indicators of compromise in alert text.

Regex finds candidates; Python validates and filters them. Complex
regex that tries to enforce correctness becomes unreadable and still
gets edge cases wrong — matching loosely and validating properly is
both simpler and more accurate.
"""

import ipaddress
import re
from typing import Any, Optional

from src import config

# ---------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------

# Loose IPv4 match. Octet ranges are validated afterwards with the
# ipaddress module rather than encoded in the pattern.
IPV4_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# Hashes are fixed-length hex. Order matters when checking: SHA256
# before SHA1 before MD5, since a longer hash contains valid
# substrings of shorter ones.
HASH_PATTERNS = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}

URL_PATTERN = re.compile(
    r"\bh(?:tt|xx)ps?://[^\s<>\"'\)\]]+",
    re.IGNORECASE,
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)

EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# Version strings, build numbers and rule IDs are structurally
# identical to IPv4 addresses. Where a match is preceded by one of
# these words, it is almost certainly not an address.
VERSION_CONTEXT = re.compile(
    r"\b(?:v|ver|version|rule|build|release|sig|signature)[\s.:]*$",
    re.IGNORECASE,
)

# Filenames and telemetry fields that look like domains but aren't
# worth enriching.
NON_DOMAIN_SUFFIXES = {
    "exe", "dll", "sys", "bat", "ps1", "sh", "py", "js", "jar",
    "zip", "rar", "7z", "tar", "gz", "doc", "docx", "xls", "xlsx",
    "pdf", "txt", "log", "json", "xml", "csv", "png", "jpg", "tmp",
    "local", "localdomain", "internal", "corp", "lan",
}


# ---------------------------------------------------------------
# Defanging
# ---------------------------------------------------------------

def refang(text: str) -> str:
    """
    Convert defanged indicators back to their real form.

    Analysts write hxxp://evil[.]com so the string does not become a
    clickable link in a ticket or chat. Input may arrive either way.
    """
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("hxxp", "http")
        .replace("hXXp", "http")
        .replace("[at]", "@")
        .replace("[@]", "@")
    )


def defang(indicator: str) -> str:
    """Make an indicator safe to paste into a ticket or chat."""
    return (
        indicator.replace("http", "hxxp")
        .replace(".", "[.]")
    )


# ---------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------

def classify_ip(candidate: str) -> Optional[str]:
    """
    Return 'public', 'private' or None for an IPv4 candidate.

    None means the string parsed as digits and dots but is not a
    valid address — 999.1.1.1, or a version number that happened to
    fall outside valid octet ranges.
    """
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None

    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return "private"

    return "public"


def _preceded_by_version_word(text: str, start: int) -> bool:
    """Check whether a match is preceded by 'v', 'rule', 'build' etc."""
    window = text[max(0, start - 20):start]
    return bool(VERSION_CONTEXT.search(window))


def _looks_like_filename(domain: str) -> bool:
    """Reject filenames and internal suffixes that match the domain pattern."""
    suffix = domain.rsplit(".", 1)[-1].lower()
    return suffix in NON_DOMAIN_SUFFIXES


# ---------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------

def extract_iocs(text: str) -> list[dict[str, Any]]:
    """
    Find all indicators in a block of text.

    Returns one record per unique indicator, carrying its type and
    whether it is worth enriching. Private addresses are kept rather
    than dropped — they identify the affected host, which the analyst
    needs, even though no external intelligence exists for them.
    """
    if not text:
        return []

    text = refang(text)
    found: dict[str, dict[str, Any]] = {}

    # Hashes first, and URLs before domains, so that substrings of a
    # longer indicator are not extracted separately.
    _extract_hashes(text, found)
    _extract_urls(text, found)
    _extract_emails(text, found)
    _extract_ips(text, found)
    _extract_domains(text, found)

    return list(found.values())


def _add(found: dict, value: str, ioc_type: str, enrichable: bool,
         note: str = "") -> None:
    """Record an indicator, keeping the first classification seen."""
    key = value.lower()
    if key in found:
        return
    found[key] = {
        "value": value,
        "type": ioc_type,
        "enrichable": enrichable,
        "note": note,
        "defanged": defang(value),
    }


def _extract_hashes(text: str, found: dict) -> None:
    # Longest first — a SHA256 string contains valid 40- and
    # 32-character hex substrings.
    for hash_type in ("sha256", "sha1", "md5"):
        for match in HASH_PATTERNS[hash_type].finditer(text):
            value = match.group()
            # Skip if this sits inside an already-recorded longer hash.
            if any(value.lower() in k for k in found if len(k) > len(value)):
                continue
            _add(found, value, hash_type, enrichable=True)


def _extract_urls(text: str, found: dict) -> None:
    for match in URL_PATTERN.finditer(text):
        url = match.group().rstrip(".,;:)")
        _add(found, url, "url", enrichable=True)


def _extract_emails(text: str, found: dict) -> None:
    for match in EMAIL_PATTERN.finditer(text):
        _add(found, match.group(), "email", enrichable=False,
             note="No reputation source configured for email addresses")


def _extract_ips(text: str, found: dict) -> None:
    for match in IPV4_PATTERN.finditer(text):
        value = match.group()

        if _preceded_by_version_word(text, match.start()):
            continue

        classification = classify_ip(value)

        if classification is None:
            continue

        if classification == "private":
            _add(found, value, "ip", enrichable=False,
                 note="Private or reserved address — internal context, "
                      "no external reputation exists")
        else:
            _add(found, value, "ip", enrichable=True)


def _extract_domains(text: str, found: dict) -> None:
    for match in DOMAIN_PATTERN.finditer(text):
        value = match.group()

        # Skip anything already captured inside a URL or email.
        if any(value.lower() in k for k in found if k != value.lower()):
            continue

        if _looks_like_filename(value):
            continue

        # A domain pattern also matches an IPv4 address.
        if IPV4_PATTERN.fullmatch(value):
            continue

        _add(found, value, "domain", enrichable=True)


def extract_from_alert(alert: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract indicators from a structured alert.

    Structured fields and free text are both searched, because tools
    vary in what they put where — the same indicator may appear in a
    dedicated field, in a description string, or in both.
    """
    parts = []

    for value in alert.values():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, (int, float)):
            continue
        elif isinstance(value, (list, dict)):
            parts.append(str(value))

    iocs = extract_iocs(" ".join(parts))

    if len(iocs) > config.MAX_IOCS_PER_ALERT:
        enrichable = [i for i in iocs if i["enrichable"]]
        rest = [i for i in iocs if not i["enrichable"]]
        iocs = (enrichable + rest)[:config.MAX_IOCS_PER_ALERT]

    return iocs