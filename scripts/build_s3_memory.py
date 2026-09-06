import csv
import json
from pathlib import Path

CASE = Path(r"C:\ForensicAgent\data\S3_USB")
OUT = CASE / "evidence_memory_s3.json"


# -------------------------------------------------
# Encoding-safe text reader
# -------------------------------------------------
def read_text_safe(path):
    for enc in ("utf-8-sig", "utf-16", "utf-16-le"):
        try:
            return path.read_text(encoding=enc)
        except UnicodeError:
            continue

    return path.read_text(
        encoding="utf-8",
        errors="ignore"
    )


records = []


# -------------------------------------------------
# 1. USBSTOR Registry
# -------------------------------------------------
p = CASE / "usbstor_registry.csv"

if p.exists():
    with p.open("r", encoding="utf-8-sig", newline="") as f:
        for i, row in enumerate(csv.DictReader(f), start=1):

            records.append({
                "evidence_id": f"USBREG-{i:04d}",
                "artifact_type": "USBSTOR Registry",
                "source":
                    r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
                "timestamp": None,
                "value":
                    f"{row.get('PSChildName','')} "
                    f"{row.get('PSPath','')}",
                "provenance": str(p)
            })


# -------------------------------------------------
# 2. MountedDevices
# -------------------------------------------------
p = CASE / "mounted_devices.txt"

if p.exists():
    records.append({
        "evidence_id": "MOUNT-0001",
        "artifact_type": "MountedDevices Registry",
        "source":
            r"HKLM\SYSTEM\MountedDevices",
        "timestamp": None,
        "value": read_text_safe(p),
        "provenance": str(p)
    })


# -------------------------------------------------
# 3. USB file metadata
# -------------------------------------------------
p = CASE / "usb_file_metadata.csv"

if p.exists():
    with p.open("r", encoding="utf-8-sig", newline="") as f:

        for i, row in enumerate(csv.DictReader(f), start=1):

            records.append({
                "evidence_id": f"USBFILE-{i:04d}",
                "artifact_type": "USB File Metadata",
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


# -------------------------------------------------
# 4. Local returned-file metadata
# -------------------------------------------------
p = CASE / "local_file_metadata.csv"

if p.exists():
    with p.open("r", encoding="utf-8-sig", newline="") as f:

        for i, row in enumerate(csv.DictReader(f), start=1):

            records.append({
                "evidence_id": f"LOCALFILE-{i:04d}",
                "artifact_type": "Local File Metadata",
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


# -------------------------------------------------
# 5. File-content artifacts
# -------------------------------------------------
for name in [
    "usb_source.txt",
    "usb_returned.txt",
]:

    p = CASE / name

    if p.exists():

        records.append({
            "evidence_id": f"FILE-{name}",
            "artifact_type": "File-system artifact",
            "source": str(p),
            "timestamp": str(p.stat().st_mtime),
            "value": read_text_safe(p),
            "provenance": str(p)
        })


# -------------------------------------------------
# Save evidence memory
# -------------------------------------------------
with OUT.open("w", encoding="utf-8") as f:

    json.dump(
        records,
        f,
        indent=2,
        ensure_ascii=False
    )


print("\nS3 EVIDENCE MEMORY")
print("=" * 70)

print("S3 evidence records :", len(records))
print("Saved to           :", OUT)

for r in records:

    print(
        r["evidence_id"],
        "|",
        r["artifact_type"],
        "|",
        r.get("timestamp")
    )