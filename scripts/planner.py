import json
from pathlib import Path

CASES = Path(r"C:\ForensicAgent\cases.json")


def choose_tools(query, available_tools):
    """
    Lightweight planner for initial validation.
    Later this function will be replaced by an LLM planner.
    """

    q = query.lower()
    selected = []

    if "powershell" in q:
        selected.append("powershell_event_search")

    if "download" in q or "executed" in q:
        for t in [
            "security_event_search",
            "prefetch_search",
            "filesystem_search"
        ]:
            if t in available_tools:
                selected.append(t)

    if "usb" in q:
        for t in [
            "usbstor_search",
            "mounted_device_search",
            "filesystem_search"
        ]:
            if t in available_tools:
                selected.append(t)

    if "persistence" in q or "startup" in q:
        for t in [
            "registry_search",
            "powershell_event_search",
            "filesystem_search"
        ]:
            if t in available_tools:
                selected.append(t)

    # Remove duplicates while keeping order
    selected = list(dict.fromkeys(selected))

    # Restrict to available tools
    selected = [
        t for t in selected
        if t in available_tools
    ]

    return selected


if __name__ == "__main__":

    with CASES.open("r", encoding="utf-8") as f:
        cases = json.load(f)

    print("\nFORENSICAGENT PLANNER")
    print("=" * 70)

    for case_id, case in cases.items():

        tools = choose_tools(
            case["query"],
            case["tools"]
        )

        print("\nCase :", case_id)
        print("Query:", case["query"])
        print("Plan :", tools)