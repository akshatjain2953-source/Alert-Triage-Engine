"""Manual check for case note generation."""

import asyncio
import json

from src import config, extract, intel, score, casenote


async def main():
    path = config.SAMPLES_DIR / "alert_suspicious_connection.json"
    with open(path, encoding="utf-8") as f:
        alert = json.load(f)

    iocs = extract.extract_from_alert(alert)
    enriched = await intel.enrich_all(iocs)
    result = score.score_alert(enriched)

    print()
    print(casenote.build_note(result, alert))
    print()
    print("=" * 72)
    print("MARKDOWN VARIANT")
    print("=" * 72)
    print()
    print(casenote.build_note_markdown(result, alert))
    print()


if __name__ == "__main__":
    asyncio.run(main())