import csv
import json
from pathlib import Path

CASE_DIR = Path(r"C:\ForensicAgent\data\S1_PowerShell")
INPUT = CASE_DIR / "powershell_events.csv"
OUTPUT = CASE_DIR / "evidence_memory.json"

records = []

with INPUT.open("r", encoding="utf-8-sig", newline="") as f:
    reader = csv.DictReader(f)

    for idx, row in enumerate(reader, start=1):
        message = (row.get("Message") or "").strip()

        record = {
            "evidence_id": f"PS-{idx:04d}",
            "artifact_type": "Windows PowerShell Event Log",
            "source": "Microsoft-Windows-PowerShell/Operational",
            "event_id": row.get("Id"),
            "timestamp": row.get("TimeCreated"),
            "level": row.get("LevelDisplayName"),
            "provider": row.get("ProviderName"),
            "value": message,
            "provenance": str(INPUT)
        }

        records.append(record)

with OUTPUT.open("w", encoding="utf-8") as f:
    json.dump(records, f, indent=2, ensure_ascii=False)

print("Evidence records :", len(records))
print("Saved to         :", OUTPUT)

for r in records[:10]:
    print(
        r["evidence_id"],
        "| Event ID:", r["event_id"],
        "|", r["timestamp"]
    )