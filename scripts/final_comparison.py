import json
import csv
from pathlib import Path

ROOT = Path(r"C:\ForensicAgent")
OUT = ROOT / "outputs"

METHODS = {
    "LLM-only": OUT / "llm_only_trace.json",
    "RAG-LLM": OUT / "rag_llm_trace.json",
    "Agent-NoVerify": OUT / "agent_execution_trace.json",
    "ForensicAgent": OUT / "verified_agent_trace.json"
}

TRUE_IDS = {"C1", "C2", "C3"}
FALSE_IDS = {"C4"}

rows = []

for method, path in METHODS.items():

    with path.open("r", encoding="utf-8") as f:
        reports = json.load(f)

    true_total = 0
    true_supported = 0

    false_total = 0
    false_supported = 0
    false_rejected = 0

    supported_total = 0
    grounded_supported = 0

    tool_calls = 0
    retrieval_calls = 0
    total_latency = 0.0

    for report in reports:

        tool_calls += report.get("tool_calls", 0)
        retrieval_calls += report.get("retrieval_calls", 0)
        total_latency += report.get("latency_seconds", 0.0)

        for claim in report.get("claims", []):

            cid = claim.get("claim_id")
            status = claim.get("status")
            evidence_ids = claim.get("evidence_ids", [])

            if cid in TRUE_IDS:
                true_total += 1

                if status == "SUPPORTED":
                    true_supported += 1

            if cid in FALSE_IDS:
                false_total += 1

                if status == "SUPPORTED":
                    false_supported += 1
                else:
                    false_rejected += 1

            if status == "SUPPORTED":

                supported_total += 1

                if evidence_ids:
                    grounded_supported += 1

    tsr = (
        true_supported / true_total
        if true_total else 0
    )

    # Evidence grounding among claims asserted as supported
    egr = (
        grounded_supported / supported_total
        if supported_total else 0
    )

    ucr = (
        false_supported / false_total
        if false_total else 0
    )

    avg_tools = (
        tool_calls / len(reports)
    )

    avg_retrieval = (
        retrieval_calls / len(reports)
    )

    avg_latency = (
        total_latency / len(reports)
    )

    rows.append({
        "Method": method,
        "TrueSupported":
            f"{true_supported}/{true_total}",
        "FalseRejected":
            f"{false_rejected}/{false_total}",
        "TSR_percent":
            round(tsr * 100, 2),
        "EGR_percent":
            round(egr * 100, 2),
        "UCR_percent":
            round(ucr * 100, 2),
        "AvgToolCalls":
            round(avg_tools, 2),
        "AvgRetrievalCalls":
            round(avg_retrieval, 2),
        "AvgLatency_s":
            round(avg_latency, 3)
    })


print("\nFINAL FORENSICAGENT COMPARISON")
print("=" * 112)

print(
    f'{"Method":<18}'
    f'{"True":<10}'
    f'{"False Rej.":<12}'
    f'{"TSR":<10}'
    f'{"EGR":<10}'
    f'{"UCR":<10}'
    f'{"Tools":<10}'
    f'{"Retrieval":<12}'
    f'{"Latency(s)"}'
)

print("-" * 112)

for r in rows:

    print(
        f'{r["Method"]:<18}'
        f'{r["TrueSupported"]:<10}'
        f'{r["FalseRejected"]:<12}'
        f'{r["TSR_percent"]:<10.2f}'
        f'{r["EGR_percent"]:<10.2f}'
        f'{r["UCR_percent"]:<10.2f}'
        f'{r["AvgToolCalls"]:<10.2f}'
        f'{r["AvgRetrievalCalls"]:<12.2f}'
        f'{r["AvgLatency_s"]:.3f}'
    )


csv_path = OUT / "final_comparison.csv"

with csv_path.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=rows[0].keys()
    )

    writer.writeheader()
    writer.writerows(rows)

print("\nSaved:", csv_path)