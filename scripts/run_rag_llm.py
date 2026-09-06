import json
import time
import requests
from pathlib import Path

from forensic_tools import load_memory

ROOT = Path(r"C:\ForensicAgent")
CASES = ROOT / "cases.json"
OUT = ROOT / "outputs" / "rag_llm_trace.json"

MODEL = "qwen2.5:3b"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

CLAIMS = {
    "S1": [
        ["C1", "Controlled PowerShell activity occurred."],
        ["C2", "Get-Process was executed."],
        ["C3", "The forensic marker was written to evidence.txt."],
        ["C4", "Invoke-Mimikatz was executed."]
    ],
    "S2": [
        ["C1", "The downloaded test BAT file existed."],
        ["C2", "cmd.exe execution occurred."],
        ["C3", "The S2 execution marker was created."],
        ["C4", "ransomware.exe was executed."]
    ],
    "S3": [
        ["C1", "A USB storage device was present."],
        ["C2", "ICA2026_USB_TEST.txt existed on the USB device."],
        ["C3", "The USB test file was transferred back to the host."],
        ["C4", "UnknownUSB_Malware.exe was executed."]
    ],
    "S4": [
        ["C1", "A startup persistence Run-key entry exists."],
        ["C2", "The Run-key entry references benign_startup.ps1."],
        ["C3", "The referenced startup script executed."],
        ["C4", "malicious_persist.exe was configured for persistence."]
    ]
}


def retrieve(memory, claim_text, k=6):

    terms = [
        x.lower().strip(".,:")
        for x in claim_text.split()
        if len(x) >= 4
    ]

    scored = []

    for item in memory:

        text = (
            str(item.get("value", "")) + " " +
            str(item.get("source", "")) + " " +
            str(item.get("path", "")) + " " +
            str(item.get("artifact_type", ""))
        ).lower()

        score = sum(
            1 for term in terms
            if term in text
        )

        if score > 0:
            scored.append(
                (score, item)
            )

    scored.sort(
        key=lambda x: x[0],
        reverse=True
    )

    return [
        item
        for _, item in scored[:k]
    ]


def format_context(records):

    blocks = []

    for e in records:

        blocks.append(
            f"""
Evidence ID: {e.get('evidence_id')}
Artifact: {e.get('artifact_type')}
Source: {e.get('source')}
Timestamp: {e.get('timestamp')}
Content: {str(e.get('value', ''))[:1200]}
"""
        )

    return "\n".join(blocks)


def ask_llm(
    query,
    claim_id,
    claim_text,
    evidence
):

    context = format_context(
        evidence
    )

    prompt = f"""
You are performing evidence-grounded cyber forensic analysis.

Investigation objective:
{query}

Candidate claim:
{claim_id}: {claim_text}

Retrieved forensic evidence:
{context}

Decide whether the candidate claim is directly supported by the
retrieved forensic evidence.

Rules:
1. Do not rely on general knowledge.
2. A claim is SUPPORTED only if retrieved evidence directly supports it.
3. Otherwise mark it UNSUPPORTED.
4. Return only evidence IDs that genuinely support the claim.
5. Return ONLY valid JSON.

Required format:
{{
  "claim_id": "{claim_id}",
  "status": "SUPPORTED",
  "evidence_ids": ["EVIDENCE-ID"]
}}
"""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1
        }
    }

    r = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=180
    )

    r.raise_for_status()

    result = json.loads(
        r.json()["response"]
    )

    status = str(
        result.get(
            "status",
            "UNSUPPORTED"
        )
    ).upper()

    if status not in [
        "SUPPORTED",
        "UNSUPPORTED"
    ]:
        status = "UNSUPPORTED"

    valid_ids = {
        e.get("evidence_id")
        for e in evidence
    }

    evidence_ids = [
        eid
        for eid in result.get(
            "evidence_ids",
            []
        )
        if eid in valid_ids
    ]

    return status, evidence_ids


with CASES.open(
    "r",
    encoding="utf-8"
) as f:
    cases = json.load(f)

reports = []

print("\nRAG-LLM BASELINE")
print("=" * 76)

for case_id, case in cases.items():

    memory = load_memory(
        case["memory"]
    )

    case_start = time.perf_counter()

    claims_out = []

    print(f"\nCASE {case_id}")

    for claim_id, claim_text in CLAIMS[case_id]:

        retrieved = retrieve(
            memory,
            claim_text,
            k=6
        )

        start = time.perf_counter()

        status, evidence_ids = ask_llm(
            case["query"],
            claim_id,
            claim_text,
            retrieved
        )

        claim_latency = (
            time.perf_counter() - start
        )

        claims_out.append({
            "claim_id": claim_id,
            "claim": claim_text,
            "status": status,
            "evidence_ids": evidence_ids,
            "retrieved_count":
                len(retrieved),
            "claim_latency_seconds":
                round(claim_latency, 6)
        })

        print(
            claim_id,
            status,
            evidence_ids,
            f"({claim_latency:.3f}s)"
        )

    case_latency = (
        time.perf_counter()
        - case_start
    )

    reports.append({
        "case_id": case_id,
        "query": case["query"],
        "tool_calls": 0,
        "retrieval_calls": 4,
        "latency_seconds":
            round(case_latency, 6),
        "claims": claims_out
    })


with OUT.open(
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        reports,
        f,
        indent=2,
        ensure_ascii=False
    )

print("\nSaved:", OUT)