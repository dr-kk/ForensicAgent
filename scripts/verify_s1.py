import json
from pathlib import Path

MEMORY = Path(
    r"C:\ForensicAgent\data\S1_PowerShell\evidence_memory.json"
)

OUTPUT = Path(
    r"C:\ForensicAgent\outputs\S1_verification.json"
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with MEMORY.open("r", encoding="utf-8") as f:
    evidence = json.load(f)


def find_evidence(required_terms, event_ids=None):
    matches = []

    for item in evidence:
        text = str(item.get("value", "")).lower()
        event_id = str(item.get("event_id", ""))

        term_match = all(
            term.lower() in text
            for term in required_terms
        )

        id_match = (
            event_ids is None or
            event_id in [str(x) for x in event_ids]
        )

        if term_match and id_match:
            matches.append(item)

    return matches


claims = [
    {
        "claim_id": "C1",
        "claim":
            "PowerShell executed the controlled S1 forensic activity.",
        "terms": ["ICA2026_FORENSIC_TEST"],
        "event_ids": [4103, 4104],
    },
    {
        "claim_id": "C2",
        "claim":
            "The investigation executed Get-Process.",
        "terms": ["Get-Process"],
        "event_ids": [4103, 4104],
    },
    {
        "claim_id": "C3",
        "claim":
            "The marker was written to evidence.txt.",
        "terms": [
            "ICA2026_FORENSIC_TEST",
            "evidence.txt"
        ],
        "event_ids": [4103, 4104],
    },

    # Deliberately false claim for verifier validation
    {
        "claim_id": "C4",
        "claim":
            "PowerShell executed Invoke-Mimikatz.",
        "terms": ["Invoke-Mimikatz"],
        "event_ids": [4103, 4104],
    }
]

results = []

for c in claims:

    matches = find_evidence(
        c["terms"],
        c["event_ids"]
    )

    if matches:
        status = "SUPPORTED"
    else:
        status = "UNSUPPORTED"

    result = {
        "claim_id": c["claim_id"],
        "claim": c["claim"],
        "status": status,
        "evidence_ids": [
            x["evidence_id"]
            for x in matches
        ],
        "evidence_count": len(matches)
    }

    results.append(result)


with OUTPUT.open("w", encoding="utf-8") as f:
    json.dump(
        results,
        f,
        indent=2,
        ensure_ascii=False
    )


print("\nFORENSICAGENT CLAIM VERIFICATION")
print("=" * 70)

for r in results:

    print("\nClaim :", r["claim_id"])
    print("Text  :", r["claim"])
    print("Status:", r["status"])

    if r["evidence_ids"]:
        print(
            "Evidence:",
            ", ".join(r["evidence_ids"])
        )
    else:
        print("Evidence: NONE")

print("\nSaved:", OUTPUT)