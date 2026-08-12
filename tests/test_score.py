"""
Tests for the scoring stage.

Several branches never execute against the sample data available
during development — RIOT classification, degraded sources, the
lower verdict bands. These are covered with constructed source
results, which is the correct way to test a branch regardless.
"""

from src import config, score


def source(source_name: str, available: bool = True, **fields):
    """
    Build one source result in the shape intel.py returns.

    The parameter is source_name rather than name because several
    sources return their own 'name' field, which would collide.
    """
    return {"source": source_name, "available": available,
            "cached": False, **fields}

def ioc(value="185.220.101.47", ioc_type="ip", **sources):
    """Build an enriched indicator with the given source results."""
    return {
        "value": value,
        "type": ioc_type,
        "enrichable": True,
        "note": "",
        "defanged": value.replace(".", "[.]"),
        "sources": sources,
    }


# ---------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------

def test_high_detection_count_scores_strongly():
    result = score.score_indicator(ioc(virustotal=source(
        "virustotal", found=True, malicious=45, suspicious=0,
        total=70, detection_ratio="45/70",
    )))
    assert result["score"] >= config.VERDICT_THRESHOLDS["escalate"]
    assert result["verdict"] == "escalate"


def test_single_detection_scores_low():
    """
    Engines disagree constantly. One detection out of seventy is
    usually a false positive, not a finding.
    """
    result = score.score_indicator(ioc(virustotal=source(
        "virustotal", found=True, malicious=1, suspicious=0,
        total=70, detection_ratio="1/70",
    )))
    assert result["score"] < config.VERDICT_THRESHOLDS["investigate"]


def test_clean_virustotal_produces_no_signals():
    result = score.score_indicator(ioc(virustotal=source(
        "virustotal", found=True, malicious=0, suspicious=0,
        total=70, detection_ratio="0/70",
    )))
    assert result["signals"] == []
    assert result["verdict"] == "close"


# ---------------------------------------------------------------
# GreyNoise — the false-positive reducer
# ---------------------------------------------------------------

def test_riot_classification_subtracts():
    """
    RIOT is GreyNoise's catalogue of known-benign common services —
    Google DNS, CDNs, update servers. These generate a large share of
    SOC false positives and should score negative.
    """
    result = score.score_indicator(ioc(
        value="8.8.8.8",
        greynoise=source("greynoise", found=True, riot=True, noise=False,
                         classification="benign", name="Google Public DNS"),
    ))
    assert any(s["points"] < 0 for s in result["signals"])
    assert result["verdict"] == "close"


def test_mass_scanner_downgrades_but_does_not_clear():
    """
    An indiscriminate scanner is not targeting this network, but it
    can still deliver a payload. Noise downgrades; it never clears.
    """
    with_noise = score.score_indicator(ioc(
        virustotal=source("virustotal", found=True, malicious=10,
                          suspicious=0, total=70, detection_ratio="10/70"),
        greynoise=source("greynoise", found=True, riot=False, noise=True,
                         classification="unknown", name=""),
    ))
    without_noise = score.score_indicator(ioc(
        virustotal=source("virustotal", found=True, malicious=10,
                          suspicious=0, total=70, detection_ratio="10/70"),
    ))
    assert with_noise["score"] < without_noise["score"]
    assert with_noise["score"] > 0


def test_malicious_scanner_gets_both_signals():
    """
    'Malicious' and 'scans everyone' are both true and both relevant.
    An analyst needs to see the classification and the context.
    """
    result = score.score_indicator(ioc(
        greynoise=source("greynoise", found=True, riot=False, noise=True,
                         classification="malicious", name="SSH Bruteforcer"),
    ))
    sources_cited = [s["source"] for s in result["signals"]]
    assert sources_cited.count("greynoise") == 2
    assert any(s["points"] > 0 for s in result["signals"])
    assert any(s["points"] < 0 for s in result["signals"])


def test_never_observed_scanning_is_a_finding():
    """
    A 404 from GreyNoise rules OUT the noise explanation, which makes
    other malicious signals more significant rather than less.
    """
    result = score.score_indicator(ioc(
        greynoise=source("greynoise", found=False, noise=False,
                         classification="not observed scanning"),
    ))
    assert result["signals"]
    assert result["signals"][0]["points"] > 0


# ---------------------------------------------------------------
# Missing and unavailable sources
# ---------------------------------------------------------------

def test_unavailable_source_is_not_a_clean_result():
    """
    A rate-limited source did not say the indicator was clean — it
    said nothing. Treating silence as an all-clear is the failure
    mode this flag exists to prevent.
    """
    result = score.score_indicator(ioc(
        virustotal=source("virustotal", available=False,
                          reason="rate limit exceeded"),
    ))
    assert result["unavailable_sources"]
    assert "virustotal" in result["unavailable_sources"][0]


def test_type_mismatch_is_not_reported_as_degraded():
    """
    GreyNoise only handles IPs. Declining a hash lookup is correct
    behaviour, not a service failure, and must not reduce confidence.
    """
    result = score.score_indicator(ioc(
        value="a" * 32, ioc_type="md5",
        greynoise=source("greynoise", available=False,
                         reason="IP addresses only"),
    ))
    assert result["unavailable_sources"] == []


def test_alert_confidence_reduced_when_sources_down():
    alert = score.score_alert([ioc(
        virustotal=source("virustotal", available=False,
                          reason="rate limit exceeded"),
    )])
    assert alert["confidence"] == "reduced"
    assert alert["degraded_sources"]


# ---------------------------------------------------------------
# Verdict bands
# ---------------------------------------------------------------

def test_verdict_bands_are_ordered():
    assert score.verdict_for_score(100) == "escalate"
    assert score.verdict_for_score(50) == "investigate"
    assert score.verdict_for_score(20) == "monitor"
    assert score.verdict_for_score(0) == "close"


def test_verdict_boundaries_are_inclusive():
    t = config.VERDICT_THRESHOLDS
    assert score.verdict_for_score(t["escalate"]) == "escalate"
    assert score.verdict_for_score(t["escalate"] - 1) == "investigate"
    assert score.verdict_for_score(t["investigate"]) == "investigate"
    assert score.verdict_for_score(t["monitor"] - 1) == "close"


def test_score_clamped_to_range():
    result = score.score_indicator(ioc(
        virustotal=source("virustotal", found=True, malicious=70,
                          suspicious=10, total=70, detection_ratio="70/70"),
        otx=source("otx", found=True, pulse_count=50, pulses=["x"], tags=[]),
        threatfox=source("threatfox", found=True,
                         malware_families=["QakBot"],
                         threat_types=["botnet_cc"], confidence=100),
    ))
    assert 0 <= result["score"] <= 100
    assert result["raw_score"] > 100  # pre-clamp total is preserved


# ---------------------------------------------------------------
# Alert-level aggregation
# ---------------------------------------------------------------

def test_alert_takes_worst_indicator_not_average():
    """
    One confirmed malicious hash among ten clean indicators is still
    a confirmed malicious hash. Averaging would dilute exactly the
    signal that matters.
    """
    bad = ioc(value="1.2.3.4", virustotal=source(
        "virustotal", found=True, malicious=50, suspicious=0,
        total=70, detection_ratio="50/70"))
    clean = [ioc(value=f"9.9.9.{i}", virustotal=source(
        "virustotal", found=True, malicious=0, suspicious=0,
        total=70, detection_ratio="0/70")) for i in range(1, 10)]

    result = score.score_alert(clean + [bad])
    assert result["verdict"] == "escalate"
    assert result["driving_indicator"] == "1.2.3.4"


def test_indicators_sorted_by_score():
    result = score.score_alert([
        ioc(value="1.1.1.1", virustotal=source(
            "virustotal", found=True, malicious=0, suspicious=0,
            total=70, detection_ratio="0/70")),
        ioc(value="2.2.2.2", virustotal=source(
            "virustotal", found=True, malicious=40, suspicious=0,
            total=70, detection_ratio="40/70")),
    ])
    scores = [i["score"] for i in result["indicators"]]
    assert scores == sorted(scores, reverse=True)


def test_context_only_indicators_do_not_drive_verdict():
    private = {
        "value": "10.0.0.1", "type": "ip", "enrichable": False,
        "note": "Private", "defanged": "10[.]0[.]0[.]1", "sources": {},
    }
    result = score.score_alert([private])
    assert result["verdict"] == "close"
    assert result["context_only_count"] == 1
    assert result["enriched_count"] == 0