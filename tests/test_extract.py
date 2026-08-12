"""
Tests for IOC extraction.

Extraction is where false positives originate: everything downstream
inherits whatever this stage decides is an indicator. The awkward
cases — version strings, filenames, private addresses — matter more
than the happy path.
"""

from src import extract


# ---------------------------------------------------------------
# IP addresses
# ---------------------------------------------------------------

def test_extracts_public_ip():
    iocs = extract.extract_iocs("Connection to 185.220.101.47 blocked")
    ips = [i for i in iocs if i["type"] == "ip"]
    assert len(ips) == 1
    assert ips[0]["value"] == "185.220.101.47"
    assert ips[0]["enrichable"] is True


def test_private_ip_kept_but_not_enrichable():
    """
    Private addresses identify the affected host, so they are useful
    context. They carry no external reputation, so enriching them
    would waste quota on a guaranteed empty result.
    """
    iocs = extract.extract_iocs("Traffic from 10.4.12.88 to 8.8.8.8")
    private = [i for i in iocs if i["value"] == "10.4.12.88"]
    assert len(private) == 1
    assert private[0]["enrichable"] is False
    assert private[0]["note"]


def test_loopback_and_link_local_not_enrichable():
    iocs = extract.extract_iocs("127.0.0.1 and 169.254.1.1 seen")
    assert all(not i["enrichable"] for i in iocs if i["type"] == "ip")


def test_invalid_octets_rejected():
    """999.999.999.999 matches the pattern but is not an address."""
    iocs = extract.extract_iocs("Bad value 999.999.999.999 logged")
    assert not [i for i in iocs if i["type"] == "ip"]


def test_version_string_not_treated_as_ip():
    """
    A version number and an IPv4 address are structurally identical.
    Only the surrounding context distinguishes them.
    """
    iocs = extract.extract_iocs("Triggered by rule v2.1.4.7 today")
    assert not [i for i in iocs if i["type"] == "ip"]


# ---------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------

def test_extracts_md5():
    h = "44d88612fea8a8f36de82e1278abb02f"
    iocs = extract.extract_iocs(f"File hash {h} observed")
    assert any(i["value"] == h and i["type"] == "md5" for i in iocs)


def test_sha256_not_split_into_shorter_hashes():
    """
    A 64-character hash contains valid 40- and 32-character hex
    substrings. Extracting those separately would triple the lookups
    for one file.
    """
    h = "a" * 64
    iocs = extract.extract_iocs(f"Hash {h}")
    hashes = [i for i in iocs if i["type"] in ("md5", "sha1", "sha256")]
    assert len(hashes) == 1
    assert hashes[0]["type"] == "sha256"


# ---------------------------------------------------------------
# URLs and domains
# ---------------------------------------------------------------

def test_url_extracted_domain_not_duplicated():
    """The domain inside a URL must not become a second indicator."""
    iocs = extract.extract_iocs("Downloaded from http://evil.example.com/x.exe")
    urls = [i for i in iocs if i["type"] == "url"]
    domains = [i for i in iocs if i["type"] == "domain"]
    assert len(urls) == 1
    assert not domains


def test_filename_not_treated_as_domain():
    iocs = extract.extract_iocs("Process payload.exe wrote config.dll")
    assert not [i for i in iocs if i["type"] == "domain"]


def test_extracts_bare_domain():
    iocs = extract.extract_iocs("Resolved cdn-delivery.example.com")
    domains = [i for i in iocs if i["type"] == "domain"]
    assert len(domains) == 1
    assert domains[0]["value"] == "cdn-delivery.example.com"


# ---------------------------------------------------------------
# Defanging
# ---------------------------------------------------------------

def test_defanged_input_still_extracted():
    """
    Indicators pasted from threat reports arrive defanged. They must
    still be recognised, or the tool fails on its most likely input.
    """
    iocs = extract.extract_iocs("Contacted 185[.]220[.]101[.]47 via hxxp://bad[.]com")
    assert any(i["value"] == "185.220.101.47" for i in iocs)
    assert any(i["type"] == "url" for i in iocs)


def test_output_is_defanged():
    iocs = extract.extract_iocs("Connection to 185.220.101.47")
    ip = next(i for i in iocs if i["type"] == "ip")
    assert ip["defanged"] == "185[.]220[.]101[.]47"


def test_url_defanging_leaves_filename_readable():
    """
    Only the scheme and host make a string clickable. Defanging the
    path makes the note harder to read for no safety benefit.
    """
    result = extract.defang("http://evil.example.com/update.exe")
    assert "update.exe" in result
    assert "evil[.]example[.]com" in result
    assert "hxxp" in result


def test_defang_refang_roundtrip():
    original = "http://evil.example.com/update.exe"
    assert extract.refang(extract.defang(original)) == original


# ---------------------------------------------------------------
# Alert-level extraction
# ---------------------------------------------------------------

def test_extracts_from_structured_and_free_text():
    """
    The same indicator may live in a dedicated field, in a description
    string, or both. Searching only one would miss half of real alerts.
    """
    alert = {
        "dest_ip": "185.220.101.47",
        "description": "Also contacted evil.example.com",
        "dest_port": 443,
    }
    iocs = extract.extract_from_alert(alert)
    values = {i["value"] for i in iocs}
    assert "185.220.101.47" in values
    assert "evil.example.com" in values


def test_no_duplicate_indicators():
    alert = {
        "dest_ip": "185.220.101.47",
        "description": "Connection to 185.220.101.47 blocked",
    }
    iocs = extract.extract_from_alert(alert)
    values = [i["value"] for i in iocs]
    assert len(values) == len(set(values))


def test_ioc_cap_enforced():
    """
    A pasted log dump could contain hundreds of indicators. Without a
    cap, one request would exhaust a daily API quota.
    """
    many = " ".join(f"185.220.101.{i}" for i in range(1, 60))
    iocs = extract.extract_from_alert({"description": many})
    assert len(iocs) <= 25


def test_empty_alert_returns_nothing():
    assert extract.extract_from_alert({}) == []
    assert extract.extract_iocs("") == []