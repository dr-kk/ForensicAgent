import csv
import json
from pathlib import Path

CASE = Path(r"C:\ForensicAgent\data\S2_DownloadExecution")
OUT = CASE / "evidence_memory_s2.json"

records = []

# Security 4688
sec = CASE / "security_4688.csv"

if sec.exists():
    with sec.open("r", encoding="utf-8-sig", newline="") as f:
        for i, row in enumerate(csv.DictReader(f), start=1):
            records.append({
                "evidence_id": f"SEC-{i:04d}",
                "artifact_type": "Windows Security Process Creation",
                "source": "Security Event Log",
                "event_id": row.get("Id"),
                "timestamp": row.get("TimeCreated"),
                "value": row.get("Message", ""),
                "provenance": str(sec)
            })

# Prefetch
pf = CASE / "prefetch_cmd.csv"

if pf.exists():
    with pf.open("r", encoding="utf-8-sig", newline="") as f:
        for i, row in enumerate(csv.DictReader(f), start=1):
            records.append({
                "evidence_id": f"PF-{i:04d}",
                "artifact_type": "Windows Prefetch",
                "source": "C:\\Windows\\Prefetch",
                "timestamp": row.get("LastWriteTime"),
                "value": row.get("Name", ""),
                "path": row.get("FullName", ""),
                "size": row.get("Length"),
                "provenance": str(pf)
            })

# File-system evidence
for name in [
    "downloaded_test.bat",
    "execution_marker.txt",
    "ground_truth.txt"
]:
    p = CASE / name

    if p.exists():
        records.append({
            "evidence_id": f"FILE-{name}",
            "artifact_type": "File-system artifact",
            "source": str(p),
            "timestamp": str(p.stat().st_mtime),
            "value": p.read_text(
                encoding="utf-8",
                errors="ignore"
            ),
            "provenance": str(p)
        })

with OUT.open("w", encoding="utf-8") as f:
    json.dump(records, f, indent=2, ensure_ascii=False)

print("S2 evidence records :", len(records))
print("Saved to           :", OUT)

for r in records:
    print(
        r["evidence_id"],
        "|",
        r["artifact_type"],
        "|",
        r.get("timestamp")
    )