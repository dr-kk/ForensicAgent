import json
import re
from pathlib import Path

ROOT = Path(r"C:\ForensicAgent\sample_data")

DROP_TERMS = [
    "ground_truth.txt",
    "Scenario=S1",
    "Scenario=S2",
    "Scenario=S3",
    "Scenario=S4",
]

GUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b"
)

for path in ROOT.rglob("*.json"):

    records = json.loads(
        path.read_text(encoding="utf-8")
    )

    cleaned = []

    for record in records:

        blob = json.dumps(
            record,
            ensure_ascii=False
        )

        if any(term in blob for term in DROP_TERMS):
            continue

        # Replace volatile host/session GUIDs
        for key, value in list(record.items()):
            if isinstance(value, str):
                record[key] = GUID_RE.sub(
                    "SANITIZED-GUID",
                    value
                )

        cleaned.append(record)

    path.write_text(
        json.dumps(
            cleaned,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print(
        f"{path}: {len(records)} -> {len(cleaned)} records"
    )