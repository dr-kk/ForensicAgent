import json
from pathlib import Path

MEMORY = Path(
    r"C:\ForensicAgent\data\S3_USB\evidence_memory_s3.json"
)

with MEMORY.open("r", encoding="utf-8") as f:
    evidence = json.load(f)


def find(term, artifact=None):
    matches = []

    for e in evidence:
        text = (
            str(e.get("value", "")) + " " +
            str(e.get("source", ""))
        ).lower()

        if term.lower() in text:
            if artifact is None or e["artifact_type"] == artifact:
                matches.append(e)

    return matches


claims = []

# C1 USB storage evidence exists
c1 = [
    e for e in evidence
    if e["artifact_type"] in [
        "USBSTOR Registry",
        "MountedDevices Registry"
    ]
]

claims.append({
    "claim": "A USB storage device was present on the host.",
    "status": "SUPPORTED" if c1 else "UNSUPPORTED",
    "evidence": [e["evidence_id"] for e in c1]
})

# C2 Test file existed on USB
c2 = find("ICA2026_USB_TEST.txt", "USB File Metadata")

claims.append({
    "claim": "ICA2026_USB_TEST.txt existed on the USB device.",
    "status": "SUPPORTED" if c2 else "UNSUPPORTED",
    "evidence": [e["evidence_id"] for e in c2]
})

# C3 File returned to host
c3_meta = find("usb_returned.txt", "Local File Metadata")
c3_marker = find("ICA2026_USB_TEST", "File-system artifact")

c3_supported = bool(c3_meta and c3_marker)

claims.append({
    "claim": "The USB test file was transferred back to the host.",
    "status": "SUPPORTED" if c3_supported else "PARTIAL",
    "evidence":
        [e["evidence_id"] for e in c3_meta] +
        [e["evidence_id"] for e in c3_marker]
})

# C4 deliberately unsupported
c4 = find("UnknownUSB_Malware.exe")

claims.append({
    "claim": "UnknownUSB_Malware.exe was executed from the USB device.",
    "status": "SUPPORTED" if c4 else "UNSUPPORTED",
    "evidence": [e["evidence_id"] for e in c4]
})

print("\nFORENSICAGENT S3 USB VERIFICATION")
print("=" * 72)

for i, c in enumerate(claims, start=1):
    print(f"\nC{i}: {c['claim']}")
    print("Status  :", c["status"])
    print(
        "Evidence:",
        ", ".join(c["evidence"]) if c["evidence"] else "NONE"
    )