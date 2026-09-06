import csv
import json
from pathlib import Path

CASE = Path(r"C:\ForensicAgent\data\S4_Persistence")
OUT = CASE / "evidence_memory_s4.json"

records = []

def read_text_safe(path):
    for enc in ("utf-8-sig", "utf-16", "utf-16-le"):
        try:
            return path.read_text(encoding=enc)
        except UnicodeError:
            continue
    return path.read_text(encoding="utf-8", errors="ignore")

# 1. Run-key evidence
p = CASE / "run_key.csv"
if p.exists():
    with p.open("r", encoding="utf-8-sig", newline="") as f:
        for i, row in enumerate(csv.DictReader(f), start=1):
            records.append({
                "evidence_id": f"RUN-{i:04d}",
                "artifact_type": "Registry Run Key",
                "source": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "timestamp": None,
                "value": " ".join(str(v) for v in row.values() if v),
                "provenance": str(p)
            })

# 2. Startup script metadata
p = CASE / "startup_script_metadata.csv"
if p.exists():
    with p.open("r", encoding="utf-8-sig", newline="") as f:
        for i, row in enumerate(csv.DictReader(f), start=1):
            records.append({
                "evidence_id": f"SCRIPT-{i:04d}",
                "artifact_type": "Startup Script Metadata",
                "source": row.get("FullName", ""),
                "timestamp": row.get("LastWriteTime"),
                "value": " ".join([
                    row.get("Name", ""),
                    row.get("FullName", ""),
                    row.get("Length", ""),
                    row.get("CreationTime", ""),
                    row.get("LastWriteTime", "")
                ]),
                "provenance": str(p)
            })

# 3. PowerShell execution evidence
p = CASE / "powershell_s4.csv"
if p.exists():
    with p.open("r", encoding="utf-8-sig", newline="") as f:
        for i, row in enumerate(csv.DictReader(f), start=1):
            records.append({
                "evidence_id": f"PS4-{i:04d}",
                "artifact_type": "PowerShell Event Log",
                "source": "Microsoft-Windows-PowerShell/Operational",
                "event_id": row.get("Id"),
                "timestamp": row.get("TimeCreated"),
                "value": row.get("Message", ""),
                "provenance": str(p)
            })

# 4. Marker evidence
p = CASE / "startup_marker.txt"
if p.exists():
    records.append({
        "evidence_id": "MARKER-0001",
        "artifact_type": "Execution Marker",
        "source": str(p),
        "timestamp": str(p.stat().st_mtime),
        "value": read_text_safe(p),
        "provenance": str(p)
    })

with OUT.open("w", encoding="utf-8") as f:
    json.dump(records, f, indent=2, ensure_ascii=False)

print("\nS4 EVIDENCE MEMORY")
print("=" * 70)
print("S4 evidence records :", len(records))
print("Saved to           :", OUT)

for r in records:
    print(
        r["evidence_id"],
        "|",
        r["artifact_type"],
        "|",
        r.get("timestamp")
    )