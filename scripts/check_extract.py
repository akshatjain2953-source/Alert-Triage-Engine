"""Manual check for the extraction stage."""

import json

from src import config, extract

path = config.SAMPLES_DIR / "alert_suspicious_connection.json"
with open(path, encoding="utf-8") as f:
    alert = json.load(f)

iocs = extract.extract_from_alert(alert)

print(f"\nExtracted {len(iocs)} indicators from {path.name}\n")
print(f"  {'Type':<8} {'Enrich':<7} {'Value':<50} Note")
print("  " + "-" * 100)

for ioc in sorted(iocs, key=lambda i: (not i["enrichable"], i["type"])):
    flag = "yes" if ioc["enrichable"] else "no"
    print(f"  {ioc['type']:<8} {flag:<7} {ioc['value'][:48]:<50} {ioc['note']}")

print()
print(f"  Enrichable: {sum(1 for i in iocs if i['enrichable'])}")
print(f"  Context only: {sum(1 for i in iocs if not i['enrichable'])}")
print()