"""Manual check for the intel clients."""

import asyncio
import json
import time

from src import config, extract, intel


async def main():
    path = config.SAMPLES_DIR / "alert_suspicious_connection.json"
    with open(path, encoding="utf-8") as f:
        alert = json.load(f)

    iocs = extract.extract_from_alert(alert)
    print(f"\n  Configured sources: {config.configured_sources()}")
    print(f"  Enriching {sum(1 for i in iocs if i['enrichable'])} indicators...\n")

    start = time.time()
    enriched = await intel.enrich_all(iocs)
    elapsed = time.time() - start

    for ioc in enriched:
        print(f"  {ioc['type']:<8} {ioc['value'][:45]}")
        if not ioc["sources"]:
            print(f"      (not enriched — {ioc['note']})")
        for name, res in sorted(ioc["sources"].items()):
            if not res["available"]:
                print(f"      {name:<12} unavailable: {res['reason']}")
            else:
                fields = {k: v for k, v in res.items()
                          if k not in ("source", "available", "cached")}
                cached = " [cached]" if res.get("cached") else ""
                print(f"      {name:<12} {fields}{cached}")
        print()

    print(f"  Completed in {elapsed:.2f}s\n")


if __name__ == "__main__":
    asyncio.run(main())