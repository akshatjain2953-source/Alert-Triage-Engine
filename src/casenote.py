"""
Case note generation: render triage results as prose.

Every sentence is assembled from values the sources actually
returned. The engine does not know whether a host is compromised —
it knows what four APIs said — and the note stays at that level.
Output that sounds more certain than the evidence is worse than no
output, because it removes the analyst's reason to look closer.

Indicators are defanged so notes are safe to paste into a ticket,
chat, or email without creating a clickable link to malicious
infrastructure.
"""

from datetime import datetime, timezone
from typing import Any

from src import config

# Recommended actions per verdict. Deliberately phrased as
# suggestions — the engine recommends and a human decides.
NEXT_STEPS = {
    "escalate": [
        "Hand to L2 with this note attached",
        "Isolate the affected host pending investigation",
        "Hunt for the same indicators across other endpoints",
        "Check whether the destination is already blocked at the perimeter",
    ],
    "investigate": [
        "Review the affected host's recent process and network activity",
        "Confirm whether the connection was user-initiated",
        "Check whether other hosts contacted the same indicators",
    ],
    "monitor": [
        "Log the indicators for correlation against future alerts",
        "No immediate containment action indicated",
    ],
    "close": [
        "Close as benign unless additional context suggests otherwise",
        "Indicators recorded for future correlation",
    ],
}


def _plural(count: int, singular: str, plural: str = None) -> str:
    return singular if count == 1 else (plural or singular + "s")


def _describe_indicator(ioc: dict[str, Any]) -> str:
    """One sentence summarising what the sources said about one indicator."""
    label = {
        "ip": "IP address",
        "domain": "Domain",
        "url": "URL",
        "md5": "File (MD5)",
        "sha1": "File (SHA1)",
        "sha256": "File (SHA256)",
        "email": "Email address",
    }.get(ioc["type"], ioc["type"])

    value = ioc.get("defanged") or ioc["value"]

    if not ioc.get("signals"):
        if not ioc.get("sources"):
            return f"{label} {value} — {ioc.get('note', 'not enriched')}."
        return f"{label} {value} — no adverse findings from any source."

    reasons = [s["reason"] for s in ioc["signals"]]
    joined = "; ".join(reasons)
    return f"{label} {value} — {joined}."


def build_summary(result: dict[str, Any], alert: dict[str, Any]) -> str:
    """The opening paragraph: what was assessed and what came back."""
    verdict = result["verdict"]
    score = result["score"]

    alert_id = alert.get("alert_id") or alert.get("id") or "this alert"
    rule = alert.get("rule_name") or alert.get("rule") or ""
    host = alert.get("source_host") or alert.get("hostname") or ""

    opening = f"Triage of {alert_id}"
    if rule:
        opening += f" (\"{rule}\")"
    if host:
        opening += f" on {host}"

    opening += (
        f" returns a recommendation of {verdict.upper()} "
        f"with a confidence score of {score}/100. "
    )

    enriched = result["enriched_count"]
    total = result["indicator_count"]
    context = result["context_only_count"]

    opening += (
        f"{total} {_plural(total, 'indicator')} were extracted, "
        f"of which {enriched} could be enriched against external "
        f"threat intelligence"
    )
    if context:
        opening += (
            f" and {context} {_plural(context, 'is', 'are')} internal "
            f"context with no external reputation"
        )
    opening += "."

    if result.get("driving_indicator") and score > 0:
        driver = next(
            (i for i in result["indicators"]
             if i["value"] == result["driving_indicator"]),
            None,
        )
        if driver:
            shown = driver.get("defanged") or driver["value"]
            opening += (
                f" The verdict is driven by {shown}, "
                f"the highest-scoring indicator in this alert."
            )

    return opening


def build_findings(result: dict[str, Any]) -> list[str]:
    """One line per indicator, highest scoring first."""
    lines = []
    for ioc in result["indicators"]:
        prefix = f"[{ioc['score']:>3}] " if ioc.get("sources") else "[  -] "
        lines.append(prefix + _describe_indicator(ioc))
    return lines


def build_caveats(result: dict[str, Any]) -> list[str]:
    """
    Explicit statements of what this assessment could not establish.

    An analyst reading a clean verdict needs to know whether it means
    "checked and clean" or "could not check". Omitting that turns a
    partial assessment into an apparent all-clear.
    """
    caveats = []

    if result.get("degraded_sources"):
        caveats.append(
            f"Assessment is incomplete — the following sources could not "
            f"be reached: {', '.join(result['degraded_sources'])}. "
            f"A clean result from a source that did not respond is not "
            f"a clean result."
        )

    if result["context_only_count"]:
        caveats.append(
            "Private and reserved addresses were not enriched. They "
            "identify internal hosts involved but carry no external "
            "reputation, since the same ranges exist in every network."
        )

    caveats.append(
        "Reputation data reflects what was known at the time of lookup. "
        "Newly registered infrastructure frequently has no reputation "
        "yet, so an absence of findings is weaker evidence than a "
        "positive finding."
    )

    return caveats


def build_note(result: dict[str, Any], alert: dict[str, Any]) -> str:
    """Assemble the full case note as plain text."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    verdict = result["verdict"]

    sections = [
        f"TRIAGE ASSESSMENT — {verdict.upper()}",
        f"Generated {generated} by alert-triage-engine",
        "",
        config.VERDICT_DESCRIPTIONS[verdict],
        "",
        "SUMMARY",
        build_summary(result, alert),
        "",
        "FINDINGS",
    ]

    sections.extend(build_findings(result))

    sections.extend(["", "RECOMMENDED NEXT STEPS"])
    sections.extend(f"- {step}" for step in NEXT_STEPS[verdict])

    sections.extend(["", "CAVEATS"])
    sections.extend(f"- {c}" for c in build_caveats(result))

    sections.extend([
        "",
        "This is an automated recommendation based on external threat "
        "intelligence lookups. It is not a determination that a host is "
        "compromised, and analyst judgement is required before acting.",
    ])

    return "\n".join(sections)


def build_note_markdown(result: dict[str, Any], alert: dict[str, Any]) -> str:
    """
    Markdown variant, for ticketing systems that render it.

    Jira, GitHub Issues and most modern SOC platforms accept markdown;
    plain text stays available for those that do not.
    """
    verdict = result["verdict"]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    badge = {
        "escalate": "🔴", "investigate": "🟠",
        "monitor": "🟡", "close": "🟢",
    }[verdict]

    lines = [
        f"## {badge} Triage assessment — {verdict.upper()} "
        f"({result['score']}/100)",
        "",
        f"*{config.VERDICT_DESCRIPTIONS[verdict]}*",
        "",
        build_summary(result, alert),
        "",
        "### Findings",
        "",
        "| Score | Indicator | Assessment |",
        "|---|---|---|",
    ]

    for ioc in result["indicators"]:
        value = ioc.get("defanged") or ioc["value"]
        score = ioc["score"] if ioc.get("sources") else "—"
        if ioc.get("signals"):
            assessment = "; ".join(s["reason"] for s in ioc["signals"])
        elif ioc.get("sources"):
            assessment = "No adverse findings"
        else:
            assessment = ioc.get("note", "Not enriched")
        lines.append(f"| {score} | `{value}` | {assessment} |")

    lines.extend(["", "### Recommended next steps", ""])
    lines.extend(f"- {step}" for step in NEXT_STEPS[verdict])

    lines.extend(["", "### Caveats", ""])
    lines.extend(f"- {c}" for c in build_caveats(result))

    lines.extend([
        "",
        f"<sub>Generated {generated} by alert-triage-engine. Automated "
        f"recommendation based on external threat intelligence — not a "
        f"determination of compromise. Analyst judgement required.</sub>",
    ])

    return "\n".join(lines)