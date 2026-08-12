"""
Scoring stage: turn enrichment results into a triage recommendation.

Scoring is additive, and every contribution carries the sentence that
justifies it. A bare numeric score is unarguable, which makes it
useless to an analyst who needs to disagree in seconds.

Evidence combines here rather than one signal trumping the rest,
because alert triage genuinely accumulates: several weak signals
pointing the same way mean more than any one of them alone.
"""

from typing import Any

from src import config


def _signal(points: int, source: str, reason: str) -> dict[str, Any]:
    """One piece of evidence: its weight, its origin, and its rationale."""
    return {"points": points, "source": source, "reason": reason}


# ---------------------------------------------------------------
# Per-source scoring
# ---------------------------------------------------------------

def score_virustotal(result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Score AV engine consensus.

    Engines disagree constantly, so a single detection is usually a
    false positive. Consensus is what carries weight.
    """
    if not result.get("available") or not result.get("found"):
        return []

    malicious = result.get("malicious", 0)
    suspicious = result.get("suspicious", 0)
    ratio = result.get("detection_ratio", "0/0")

    signals = []

    if malicious >= config.VT_MALICIOUS_THRESHOLD:
        # Scale with consensus. Overwhelming agreement across engines
        # is sufficient on its own — no analyst treats 45 of 70 as
        # ambiguous — so the cap sits above the escalate threshold
        # rather than below it. Ten detections still lands in
        # "investigate", which is where it belongs.
        points = min(30 + malicious * 2, 75)
        signals.append(_signal(
            points, "virustotal",
            f"{ratio} engines flag this as malicious",
        ))
    elif malicious >= config.VT_SUSPICIOUS_THRESHOLD:
        signals.append(_signal(
            15, "virustotal",
            f"{ratio} engines flag this — below consensus threshold, "
            f"could be a false positive",
        ))
    elif malicious == 1:
        signals.append(_signal(
            5, "virustotal",
            f"{ratio} engines flag this — single detection, low confidence",
        ))

    if suspicious >= 3:
        signals.append(_signal(
            8, "virustotal",
            f"{suspicious} engines mark this suspicious",
        ))

    return signals


def score_greynoise(result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Score internet-background-noise context.

    This is the only source that can subtract. An IP scanning the
    entire internet is not targeting this network — it hit fifty
    thousand others the same day, which is also why it accumulates
    abuse reports elsewhere.

    Malicious classification and mass-scanning behaviour are not
    mutually exclusive: a known-bad scanner is still opportunistic,
    and an analyst needs both facts to judge whether the alert
    represents targeting or background noise.
    """
    if not result.get("available"):
        return []

    signals = []

    # Never observed scanning. Rules out the noise explanation, which
    # makes any other malicious signal more significant.
    if not result.get("found"):
        signals.append(_signal(
            5, "greynoise",
            "not observed in internet-wide scanning — if malicious, "
            "this was likely targeted rather than opportunistic",
        ))
        return signals

    classification = result.get("classification", "unknown")
    name = result.get("name", "")
    label = f" ({name})" if name and name.lower() != "unknown" else ""

    # RIOT = known-benign common services (Google DNS, CDNs, Microsoft
    # update infrastructure). Nothing else applies if this is set.
    if result.get("riot"):
        signals.append(_signal(
            -30, "greynoise",
            f"known benign service infrastructure{label}",
        ))
        return signals

    if classification == "malicious":
        signals.append(_signal(
            25, "greynoise",
            f"classified as malicious scanning activity{label}",
        ))

    # Mass scanning stays relevant even for a malicious scanner: it
    # means this host hit thousands of networks indiscriminately
    # rather than selecting this one.
    if result.get("noise"):
        if classification == "malicious":
            signals.append(_signal(
                -15, "greynoise",
                "also seen scanning indiscriminately — opportunistic "
                "rather than targeted at this network",
            ))
        elif classification in config.GREYNOISE_NOISE_CLASSIFICATIONS:
            signals.append(_signal(
                -25, "greynoise",
                f"indiscriminate internet-wide scanner{label} — "
                f"not targeting this network specifically",
            ))

    return signals


def _clean_tags(tags: list[str]) -> list[str]:
    """
    Filter OTX pulse tags down to ones that read as threat labels.

    Pulse tags are free text typed by researchers, so they include
    dates, sample counts and other indicators copied from the same
    report. Surfacing those in a case note makes the output look
    broken, so anything numeric or implausibly long is dropped.
    """
    cleaned = []
    for tag in tags:
        if not tag or not (2 < len(tag) < 30):
            continue
        # Drop dates, counts and defanged indicators.
        stripped = tag.replace("-", "").replace(".", "").replace("_", "")
        if stripped.isdigit():
            continue
        # Drop anything mostly digits — 152x, 20060921abc and similar.
        if sum(c.isdigit() for c in tag) > len(tag) / 2:
            continue
        cleaned.append(tag)
    return cleaned


def score_otx(result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Score threat-campaign association.

    A pulse count says researchers have written this indicator into
    published reports. The campaign name matters more than the number
    — it tells an analyst what to look for next.
    """
    if not result.get("available") or not result.get("found"):
        return []

    count = result.get("pulse_count", 0)
    if count < config.OTX_PULSE_THRESHOLD:
        return []

    tags = _clean_tags(result.get("tags", []))
    pulses = result.get("pulses", [])

    points = min(10 + count * 3, 30)
    reason = f"referenced in {count} published threat report" \
             f"{'s' if count != 1 else ''}"

    # Pulse names are written deliberately; tags are free text and
    # frequently contain file attributes, dates or internal report
    # labels rather than threat classifications.
    if pulses:
        reason += f" — including \"{pulses[0][:60]}\""
    elif tags:
        reason += f" — tagged {', '.join(tags[:3])}"

    return [_signal(points, "otx", reason)]


def score_threatfox(result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Score malware family association.

    The strongest single signal available, because it is specific.
    "Tied to QakBot C2" tells an analyst what to hunt for next in a
    way that no detection ratio can.
    """
    if not result.get("available") or not result.get("found"):
        return []

    families = result.get("malware_families", [])
    threat_types = result.get("threat_types", [])
    confidence = result.get("confidence", 0)

    if not families:
        return []

    if confidence >= config.THREATFOX_CONFIDENCE_THRESHOLD:
        points = 40
        qualifier = ""
    else:
        points = 20
        qualifier = f" (reported confidence {confidence}%)"

    reason = f"associated with {', '.join(families[:3])}"
    if threat_types:
        reason += f" — {threat_types[0].replace('_', ' ')}"
    reason += qualifier

    return [_signal(points, "threatfox", reason)]


SOURCE_SCORERS = {
    "virustotal": score_virustotal,
    "greynoise": score_greynoise,
    "otx": score_otx,
    "threatfox": score_threatfox,
}


# ---------------------------------------------------------------
# Per-indicator
# ---------------------------------------------------------------

def score_indicator(ioc: dict[str, Any]) -> dict[str, Any]:
    """Score one enriched indicator, collecting every supporting signal."""
    signals: list[dict[str, Any]] = []
    unavailable: list[str] = []

    for name, result in ioc.get("sources", {}).items():
        if not result.get("available"):
            # Distinguish "we could not check" from "we checked and it
            # was clean" — a rate-limited source is not a clean result.
            reason = result.get("reason", "unavailable")
            if "unsupported" not in reason and "only" not in reason:
                unavailable.append(f"{name} ({reason})")
            continue

        scorer = SOURCE_SCORERS.get(name)
        if scorer:
            signals.extend(scorer(result))

    raw = sum(s["points"] for s in signals)
    score = max(0, min(100, raw))

    scored = dict(ioc)
    scored["signals"] = sorted(signals, key=lambda s: -abs(s["points"]))
    scored["score"] = score
    scored["raw_score"] = raw
    scored["unavailable_sources"] = unavailable
    scored["verdict"] = verdict_for_score(score)
    return scored


def verdict_for_score(score: int) -> str:
    """Map a numeric score onto a verdict band."""
    if score >= config.VERDICT_THRESHOLDS["escalate"]:
        return "escalate"
    if score >= config.VERDICT_THRESHOLDS["investigate"]:
        return "investigate"
    if score >= config.VERDICT_THRESHOLDS["monitor"]:
        return "monitor"
    return "close"


# ---------------------------------------------------------------
# Per-alert
# ---------------------------------------------------------------

def score_alert(iocs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Produce an overall verdict for an alert from its indicators.

    The alert takes its worst indicator's verdict rather than an
    average. One confirmed malicious hash in an alert containing ten
    benign indicators is still a confirmed malicious hash — averaging
    would dilute exactly the signal that matters.
    """
    scored = [score_indicator(i) for i in iocs]

    enriched = [i for i in scored if i.get("sources")]
    context_only = [i for i in scored if not i.get("sources")]

    if enriched:
        worst = max(enriched, key=lambda i: i["score"])
        overall_score = worst["score"]
        overall_verdict = worst["verdict"]
        driver = worst["value"]
    else:
        overall_score = 0
        overall_verdict = "close"
        driver = None

    # Surface any source that could not be reached. A verdict reached
    # with two of four sources down deserves less confidence, and the
    # analyst should be told rather than left to assume completeness.
    degraded = sorted({
        s for i in scored for s in i.get("unavailable_sources", [])
    })

    scored.sort(key=lambda i: (-i["score"], i["type"]))

    return {
        "verdict": overall_verdict,
        "verdict_description": config.VERDICT_DESCRIPTIONS[overall_verdict],
        "score": overall_score,
        "driving_indicator": driver,
        "indicators": scored,
        "indicator_count": len(scored),
        "enriched_count": len(enriched),
        "context_only_count": len(context_only),
        "degraded_sources": degraded,
        "confidence": "reduced" if degraded else "normal",
    }