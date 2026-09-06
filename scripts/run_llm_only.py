import json
import time
import requests
from pathlib import Path

ROOT = Path(r"C:\ForensicAgent")
CASES = ROOT / "cases.json"
OUT = ROOT / "outputs" / "llm_only_trace.json"

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


def ask_claim(query, claim_id, claim_text):

    prompt = f"""
You are evaluating a cyber forensic investigation.

Investigation objective:
{query}

Candidate claim:
{claim_id}: {claim_text}

You have NO access to forensic evidence, logs, files, Registry data,
retrieved context, or forensic tools.

Decide whether the claim can be established.

Return ONLY valid JSON:
{{
  "claim_id": "{claim_id}",
  "status": "SUPPORTED"
}}

The status must be exactly one of:
SUPPORTED
UNSUPPORTED

Do not add explanation.
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
        result.get("status", "UNSUPPORTED")
    ).upper()

    if status not in [
        "SUPPORTED",
        "UNSUPPORTED"
    ]:
        status = "UNSUPPORTED"

    return status


with CASES.open(
    "r",
    encoding="utf-8"
) as f:
    cases = json.load(f)

reports = []

print("\nLLM-ONLY BASELINE")
print("=" * 72)

for case_id, case in cases.items():

    case_start = time.perf_counter()
    claims_out = []

    print(f"\nCASE {case_id}")

    for claim_id, claim_text in CLAIMS[case_id]:

        start = time.perf_counter()

        status = ask_claim(
            case["query"],
            claim_id,
            claim_text
        )

        claim_latency = (
            time.perf_counter() - start
        )

        claims_out.append({
            "claim_id": claim_id,
            "claim": claim_text,
            "status": status,
            "evidence_ids": [],
            "claim_latency_seconds":
                round(claim_latency, 6)
        })

        print(
            claim_id,
            status,
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
