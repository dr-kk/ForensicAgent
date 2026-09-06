import json
from pathlib import Path

MEMORY = Path(
    r"C:\ForensicAgent\data\S2_DownloadExecution\evidence_memory_s2.json"
)

with MEMORY.open("r", encoding="utf-8") as f:
    evidence = json.load(f)


def search(term, artifact=None):
    matches = []

    for e in evidence:
        text = (
            str(e.get("value", "")) + " " +
            str(e.get("path", "")) + " " +
            str(e.get("source", ""))
        ).lower()

        if term.lower() in text:
            if artifact is None or e["artifact_type"] == artifact:
                matches.append(e)

    return matches


claims = []

# Claim 1: test BAT existed
c1 = search("downloaded_test.bat")

claims.append({
    "claim": "The downloaded test BAT file existed.",
    "status": "SUPPORTED" if c1 else "UNSUPPORTED",
    "evidence": [x["evidence_id"] for x in c1]
})

# Claim 2: CMD execution evidence
c2_security = search(
    "cmd.exe",
    "Windows Security Process Creation"
)

c2_prefetch = search(
    "CMD.EXE",
    "Windows Prefetch"
)

c2_supported = bool(c2_security and c2_prefetch)

claims.append({
    "claim": "cmd.exe execution is supported by independent artifacts.",
    "status": "SUPPORTED" if c2_supported else "PARTIAL",
    "evidence":
        [x["evidence_id"] for x in c2_security] +
        [x["evidence_id"] for x in c2_prefetch]
})

# Claim 3: execution marker produced
c3 = search("ICA2026_S2_EXECUTION")

claims.append({
    "claim": "The S2 execution marker was created.",
    "status": "SUPPORTED" if c3 else "UNSUPPORTED",
    "evidence": [x["evidence_id"] for x in c3]
})

# False claim
c4 = search("ransomware.exe")

claims.append({
    "claim": "ransomware.exe was executed.",
    "status": "SUPPORTED" if c4 else "UNSUPPORTED",
    "evidence": [x["evidence_id"] for x in c4]
})

print("\nFORENSICAGENT S2 CROSS-ARTIFACT VERIFICATION")
print("=" * 72)

for i, c in enumerate(claims, start=1):
    print(f"\nC{i}: {c['claim']}")
    print("Status  :", c["status"])
    print(
        "Evidence:",
        ", ".join(c["evidence"])
        if c["evidence"] else "NONE"
    )