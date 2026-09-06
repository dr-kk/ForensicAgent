import json
import time
from pathlib import Path
from llm_planner import plan_tools

from planner import choose_tools
from forensic_tools import load_memory, execute_tool

ROOT = Path(r"C:\ForensicAgent")
CASES = ROOT / "cases.json"
OUTDIR = ROOT / "outputs"
OUTDIR.mkdir(parents=True, exist_ok=True)


def minimal_evidence(results, limit_per_tool=2):
    """
    Keep only a compact evidence set.
    This avoids flooding the report with dozens of matching artifacts.
    """
    compact = []

    seen = set()

    for tool_name, items in results.items():

        count = 0

        for item in items:

            eid = item.get("evidence_id")

            if not eid or eid in seen:
                continue

            compact.append(item)
            seen.add(eid)

            count += 1

            if count >= limit_per_tool:
                break

    return compact


def generate_candidate_claims(case_id):
    """
    Controlled candidate claims for the initial end-to-end validation.
    LLM-based claim generation will replace this later.
    """

    claims = {

        "S1": [
            {
                "id": "C1",
                "text": "Controlled PowerShell activity occurred.",
                "terms": ["ICA2026_FORENSIC_TEST"]
            },
            {
                "id": "C2",
                "text": "Get-Process was executed.",
                "terms": ["Get-Process"]
            },
            {
                "id": "C3",
                "text": "The forensic marker was written to evidence.txt.",
                "terms": ["ICA2026_FORENSIC_TEST", "evidence.txt"]
            },
            {
                "id": "C4",
                "text": "Invoke-Mimikatz was executed.",
                "terms": ["Invoke-Mimikatz"]
            }
        ],

        "S2": [
            {
                "id": "C1",
                "text": "The downloaded test BAT file existed.",
                "terms": ["downloaded_test.bat"]
            },
            {
                "id": "C2",
                "text": "cmd.exe execution occurred.",
                "terms": ["cmd.exe"]
            },
            {
                "id": "C3",
                "text": "The S2 execution marker was created.",
                "terms": ["ICA2026_S2_EXECUTION"]
            },
            {
                "id": "C4",
                "text": "ransomware.exe was executed.",
                "terms": ["ransomware.exe"]
            }
        ],

        "S3": [
            {
                "id": "C1",
                "text": "A USB storage device was present.",
                "artifact_types": [
                    "USBSTOR Registry",
                    "MountedDevices Registry"
                ]
            },
            {
                "id": "C2",
                "text": "ICA2026_USB_TEST.txt existed on the USB device.",
                "terms": ["ICA2026_USB_TEST.txt"]
            },
            {
                "id": "C3",
                "text": "The USB test file was transferred back to the host.",
                "terms": ["usb_returned.txt"]
            },
            {
                "id": "C4",
                "text": "UnknownUSB_Malware.exe was executed.",
                "terms": ["UnknownUSB_Malware.exe"]
            }
        ],

        "S4": [
            {
                "id": "C1",
                "text": "A startup persistence Run-key entry exists.",
                "terms": ["ICA2026_ForensicTest"]
            },
            {
                "id": "C2",
                "text": "The Run-key entry references benign_startup.ps1.",
                "terms": ["benign_startup.ps1"]
            },
            {
                "id": "C3",
                "text": "The referenced startup script executed.",
                "terms": ["ICA2026_S4_STARTUP"]
            },
            {
                "id": "C4",
                "text": "malicious_persist.exe was configured for persistence.",
                "terms": ["malicious_persist.exe"]
            }
        ]
    }

    return claims[case_id]


def verify_claim(claim, evidence):
    matches = []

    if "artifact_types" in claim:

        for e in evidence:

            if e.get("artifact_type") in claim["artifact_types"]:
                matches.append(e)

    else:

        terms = [
            x.lower()
            for x in claim.get("terms", [])
        ]

        for e in evidence:

            text = (
                str(e.get("value", "")) + " " +
                str(e.get("source", "")) + " " +
                str(e.get("path", ""))
            ).lower()

            if all(term in text for term in terms):
                matches.append(e)

    status = (
        "SUPPORTED"
        if matches
        else "UNSUPPORTED"
    )

    return {
        "claim_id": claim["id"],
        "claim": claim["text"],
        "status": status,
        "evidence_ids": [
            x.get("evidence_id")
            for x in matches[:3]
        ]
    }


def run_case(case_id, case):

    start = time.perf_counter()

    memory = load_memory(
        case["memory"]
    )

    llm_plan = plan_tools(
    case["query"],
    case["tools"]
    )

    plan = llm_plan["selected_tools"]
    plan_reason = llm_plan["reason"]

    # Step 2: Execute tools
    tool_results = {}

    for tool in plan:

        tool_results[tool] = execute_tool(
            tool,
            memory,
            case["query"]
        )

    # Step 3: Compact evidence memory
    evidence = minimal_evidence(
        tool_results,
        limit_per_tool=10
    )

    # Step 4: Generate candidate claims
    claims = generate_candidate_claims(
        case_id
    )

    # Step 5: Verify
    verified = []

    for claim in claims:

        verified.append(
            verify_claim(
                claim,
                evidence
            )
        )

    latency = (
        time.perf_counter() - start
    )

    report = {
        "case_id": case_id,
        "query": case["query"],
        "plan": plan,
        "tool_calls": len(plan),
        "retrieved_evidence_count":
            len(evidence),
        "latency_seconds":
            round(latency, 6),
        "claims": verified
    }

    return report


def main():

    with CASES.open(
        "r",
        encoding="utf-8"
    ) as f:

        cases = json.load(f)

    all_reports = []

    print(
        "\nFORENSICAGENT END-TO-END EXECUTION"
    )
    print("=" * 75)

    for case_id, case in cases.items():

        report = run_case(
            case_id,
            case
        )

        all_reports.append(
            report
        )

        print(
            f"\nCASE {case_id}"
        )

        print(
            "Plan:",
            report["plan"]
        )

        print(
            "Tool calls:",
            report["tool_calls"]
        )

        print(
            "Evidence:",
            report[
                "retrieved_evidence_count"
            ]
        )

        print(
            "Latency:",
            report[
                "latency_seconds"
            ],
            "s"
        )

        for c in report["claims"]:

            print(
                f'  {c["claim_id"]}: '
                f'{c["status"]} '
                f'{c["evidence_ids"]}'
            )

    out = (
        OUTDIR /
        "agent_execution_trace.json"
    )

    with out.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            all_reports,
            f,
            indent=2,
            ensure_ascii=False
        )

    print(
        "\nSaved:",
        out
    )


if __name__ == "__main__":
    main()