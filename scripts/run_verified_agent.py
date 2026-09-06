import json
import time
import requests
from pathlib import Path

from llm_planner import plan_tools, MODEL, OLLAMA_URL
from forensic_tools import load_memory, execute_tool
from run_agent import (
    minimal_evidence,
    generate_candidate_claims,
    verify_claim
)

ROOT = Path(r"C:\ForensicAgent")
CASES = ROOT / "cases.json"
OUTDIR = ROOT / "outputs"
OUTDIR.mkdir(parents=True, exist_ok=True)


def replan_for_claim(
    query,
    claim,
    selected_tools,
    available_tools
):
    remaining = [
        t for t in available_tools
        if t not in selected_tools
    ]

    if not remaining:
        return []

    prompt = f"""
You are the verification and recovery planner of a digital forensic agent.

Investigation objective:
{query}

Candidate claim that currently lacks supporting evidence:
{claim}

Tools already executed:
{json.dumps(selected_tools)}

Remaining available forensic tools:
{json.dumps(remaining)}

Decide whether one or more remaining tools could provide direct or
independent evidence for this claim.

Rules:
1. Use only remaining tools.
2. Do not invent tools.
3. Select a tool only if it can materially help verify the claim.
4. If no remaining tool is useful, return an empty list.
5. Prefer the minimum sufficient additional evidence.
6. Return ONLY valid JSON.

Format:
{{
  "additional_tools": ["tool_name"],
  "reason": "brief explanation"
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

    tools = [
        t for t in result.get(
            "additional_tools", []
        )
        if t in remaining
    ]

    return tools


def run_case(case_id, case):

    start = time.perf_counter()

    memory = load_memory(
        case["memory"]
    )

    # ------------------------------------------------
    # Round 1: LLM planning
    # ------------------------------------------------

    initial = plan_tools(
        case["query"],
        case["tools"]
    )

    plan = list(
        initial["selected_tools"]
    )

    tool_results = {}

    for tool in plan:
        tool_results[tool] = execute_tool(
            tool,
            memory,
            case["query"]
        )

    evidence = minimal_evidence(
        tool_results,
        limit_per_tool=10
    )

    claims = generate_candidate_claims(
        case_id
    )

    first_pass = [
        verify_claim(c, evidence)
        for c in claims
    ]

    # ------------------------------------------------
    # Round 2: evidence-driven re-planning
    # ------------------------------------------------

    extra_tools = []

    for claim, result in zip(
        claims,
        first_pass
    ):

        if result["status"] == "SUPPORTED":
            continue

        proposed = replan_for_claim(
            case["query"],
            claim["text"],
            plan + extra_tools,
            case["tools"]
        )

        for tool in proposed:

            if (
                tool not in plan
                and tool not in extra_tools
            ):
                extra_tools.append(tool)

    # Execute newly requested tools
    for tool in extra_tools:

        tool_results[tool] = execute_tool(
            tool,
            memory,
            case["query"]
        )

    # ------------------------------------------------
    # Final evidence + verification
    # ------------------------------------------------

    evidence = minimal_evidence(
        tool_results,
        limit_per_tool=10
    )

    final_claims = [
        verify_claim(c, evidence)
        for c in claims
    ]

    latency = (
        time.perf_counter()
        - start
    )

    report = {
        "case_id": case_id,
        "query": case["query"],
        "planner": MODEL,

        "initial_plan":
            plan,

        "additional_tools":
            extra_tools,

        "final_plan":
            plan + extra_tools,

        "tool_calls":
            len(plan) + len(extra_tools),

        "retrieved_evidence_count":
            len(evidence),

        "latency_seconds":
            round(latency, 6),

        "claims":
            final_claims
    }

    return report


def main():

    with CASES.open(
        "r",
        encoding="utf-8"
    ) as f:
        cases = json.load(f)

    reports = []

    print(
        "\nFORENSICAGENT VERIFIED AGENTIC EXECUTION"
    )
    print("=" * 78)

    for case_id, case in cases.items():

        report = run_case(
            case_id,
            case
        )

        reports.append(report)

        print(
            f"\nCASE {case_id}"
        )

        print(
            "Initial plan :",
            report["initial_plan"]
        )

        print(
            "Added tools  :",
            report["additional_tools"]
        )

        print(
            "Final plan   :",
            report["final_plan"]
        )

        print(
            "Tool calls   :",
            report["tool_calls"]
        )

        print(
            "Latency      :",
            report["latency_seconds"],
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
        "verified_agent_trace.json"
    )

    with out.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            reports,
            f,
            indent=2,
            ensure_ascii=False
        )

    print("\nSaved:", out)


if __name__ == "__main__":
    main()