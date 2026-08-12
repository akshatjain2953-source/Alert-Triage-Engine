"""Manual check for the scoring stage."""

import asyncio
import json

from src import config, extract, intel, score


async def main():
    path = config.SAMPLES_DIR / "alert_suspicious_connection.json"
    with open(path, encoding="utf-8") as f:
        alert = json.load(f)

    iocs = extract.extract_from_alert(alert)
    enriched = await intel.enrich_all(iocs)
    result = score.score_alert(enriched)

    print()
    print("=" * 72)
    print(f"  VERDICT: {result['verdict'].upper()}   (score {result['score']}/100)")
    print(f"  {result['verdict_description']}")
    print("=" * 72)
    print()

    if result["driving_indicator"]:
        print(f"  Driven by: {result['driving_indicator']}")
    print(f"  Indicators: {result['indicator_count']} "
          f"({result['enriched_count']} enriched, "
          f"{result['context_only_count']} context only)")

    if result["degraded_sources"]:
        print(f"  ! Reduced confidence — unavailable: "
              f"{', '.join(result['degraded_sources'])}")
    print()

    for ioc in result["indicators"]:
        print(f"  [{ioc['score']:>3}] {ioc['verdict']:<12} "
              f"{ioc['type']:<7} {ioc['value'][:45]}")

        for sig in ioc["signals"]:
            sign = "+" if sig["points"] >= 0 else ""
            print(f"          {sign}{sig['points']:>4}  "
                  f"{sig['source']:<11} {sig['reason']}")

        if not ioc["signals"] and ioc.get("sources"):
            print(f"          no signals — all sources returned clean")
        elif not ioc.get("sources"):
            print(f"          {ioc['note']}")
        print()


if __name__ == "__main__":
    asyncio.run(main())