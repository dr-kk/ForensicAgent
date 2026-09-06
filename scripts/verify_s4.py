import json
from pathlib import Path

MEMORY = Path(
    r"C:\ForensicAgent\data\S4_Persistence\evidence_memory_s4.json"
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

# C1 Run key exists
c1 = find("ICA2026_ForensicTest", "Registry Run Key")

claims.append({
    "claim": "A startup persistence Run-key entry exists.",
    "status": "SUPPORTED" if c1 else "UNSUPPORTED",
    "evidence": [e["evidence_id"] for e in c1]
})

# C2 Run key references the benign startup script
c2_run = find("benign_startup.ps1", "Registry Run Key")
c2_file = find("benign_startup.ps1", "Startup Script Metadata")

claims.append({
    "claim": "The Run-key entry references benign_startup.ps1.",
    "status": "SUPPORTED" if c2_run and c2_file else "PARTIAL",
    "evidence":
        [e["evidence_id"] for e in c2_run] +
        [e["evidence_id"] for e in c2_file]
})

# C3 script execution evidence
c3_log = find("benign_startup", "PowerShell Event Log")
c3_marker = find("ICA2026_S4_STARTUP", "Execution Marker")

claims.append({
    "claim": "The referenced startup script executed.",
    "status": "SUPPORTED" if c3_log and c3_marker else "PARTIAL",
    "evidence":
        [e["evidence_id"] for e in c3_log] +
        [e["evidence_id"] for e in c3_marker]
})

# C4 deliberately false claim
c4 = find("malicious_persist.exe")

claims.append({
    "claim": "malicious_persist.exe was configured for startup persistence.",
    "status": "SUPPORTED" if c4 else "UNSUPPORTED",
    "evidence": [e["evidence_id"] for e in c4]
})

print("\nFORENSICAGENT S4 PERSISTENCE VERIFICATION")
print("=" * 72)

for i, c in enumerate(claims, start=1):
    print(f"\nC{i}: {c['claim']}")
    print("Status  :", c["status"])
    print(
        "Evidence:",
        ", ".join(c["evidence"]) if c["evidence"] else "NONE"
    )