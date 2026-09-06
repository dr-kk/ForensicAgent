import json
from pathlib import Path
from datetime import datetime

MEMORY = Path(
    r"C:\ForensicAgent\data\S1_PowerShell\evidence_memory.json"
)

with MEMORY.open("r", encoding="utf-8") as f:
    evidence = json.load(f)

keywords = [
    "powershell",
    "export-csv",
    "out-file",
    "get-process",
    "forensicagent",
    "ica2026_forensic_test"
]

matches = []

for item in evidence:
    text = (
        str(item.get("value", "")) + " " +
        str(item.get("event_id", "")) + " " +
        str(item.get("provider", ""))
    ).lower()

    score = sum(1 for k in keywords if k.lower() in text)

    if score > 0:
        item["retrieval_score"] = score
        matches.append(item)

matches.sort(
    key=lambda x: x["retrieval_score"],
    reverse=True
)

print("Total evidence records :", len(evidence))
print("Relevant records       :", len(matches))
print()

for x in matches[:20]:
    print("=" * 80)
    print("Evidence ID :", x["evidence_id"])
    print("Event ID    :", x["event_id"])
    print("Timestamp   :", x["timestamp"])
    print("Score       :", x["retrieval_score"])
    print("Source      :", x["source"])
    print("Message     :", x["value"][:700].replace("\r", " ").replace("\n", " "))