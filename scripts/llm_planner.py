import json
import requests

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "qwen2.5:3b"

TOOL_DESCRIPTIONS = {
    "powershell_event_search":
        "Search Windows PowerShell Operational events such as 4103 and 4104 "
        "for command execution and script-block evidence.",

    "security_event_search":
        "Search Windows Security process-creation events such as Event ID 4688 "
        "to identify executed processes.",

    "prefetch_search":
        "Search Windows Prefetch artifacts to provide independent evidence "
        "that an executable was run.",

    "filesystem_search":
        "Search file-system artifacts, metadata, scripts, execution markers, "
        "and transferred files.",

    "usbstor_search":
        "Search the USBSTOR Registry for evidence that USB storage devices "
        "were connected to the host.",

    "mounted_device_search":
        "Search MountedDevices Registry artifacts to identify mounted removable "
        "storage and associated device mappings.",

    "registry_search":
        "Search Windows Registry persistence artifacts, including the "
        "CurrentVersion Run key used for startup persistence."
}


def plan_tools(query, available_tools):

    available = {
        tool: TOOL_DESCRIPTIONS[tool]
        for tool in available_tools
    }

    prompt = f"""
You are a digital forensic investigation planning agent.

Investigation objective:
{query}

Available tools and their forensic purposes:
{json.dumps(available, indent=2)}

Select the minimum sufficient set of forensic tools required to answer
the investigation objective with reliable and preferably independent
supporting evidence.

Important forensic rules:
1. Use only tools listed above.
2. Do not invent tools.
3. Startup or Run-key persistence requires Registry examination.
4. Process execution should preferably be corroborated by more than one
   independent artifact when such tools are available.
5. USB investigations should examine device-presence evidence and file
   activity when both are available.
6. Select evidence sources that directly support the requested claims.
7. Return ONLY valid JSON.

Required format:
{{
  "selected_tools": ["tool1", "tool2"],
  "reason": "brief forensic justification"
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

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=180
    )

    response.raise_for_status()

    data = response.json()
    result = json.loads(data["response"])

    selected = [
        tool for tool in result.get("selected_tools", [])
        if tool in available_tools
    ]

    return {
        "selected_tools": selected,
        "reason": result.get("reason", "")
    }


if __name__ == "__main__":

    with open(
        r"C:\ForensicAgent\cases.json",
        "r",
        encoding="utf-8"
    ) as f:
        cases = json.load(f)

    print("\nDOMAIN-AWARE LLM FORENSIC PLANNER")
    print("=" * 72)

    for case_id, case in cases.items():

        result = plan_tools(
            case["query"],
            case["tools"]
        )

        print("\nCase :", case_id)
        print("Query:", case["query"])
        print("Tools:", result["selected_tools"])
        print("Why  :", result["reason"])