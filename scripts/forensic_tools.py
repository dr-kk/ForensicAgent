import json
from pathlib import Path


def load_memory(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def search(memory, terms, artifact_types=None, limit=5):

    if isinstance(terms, str):
        terms = [terms]

    results = []

    for item in memory:

        text = (
            str(item.get("value", "")) + " " +
            str(item.get("source", "")) + " " +
            str(item.get("path", "")) + " " +
            str(item.get("event_id", ""))
        ).lower()

        score = sum(
            1 for term in terms
            if term.lower() in text
        )

        if score == 0:
            continue

        if artifact_types:
            if item.get("artifact_type") not in artifact_types:
                continue

        result = dict(item)
        result["retrieval_score"] = score

        results.append(result)

    results.sort(
        key=lambda x: x["retrieval_score"],
        reverse=True
    )

    return results[:limit]


def execute_tool(tool_name, memory, query):

    # ---------------------------------------------------------
    # PowerShell forensic events
    # ---------------------------------------------------------
    if tool_name == "powershell_event_search":

        candidates = []

        for item in memory:

            if item.get("artifact_type") not in [
                "Windows PowerShell Event Log",
                "PowerShell Event Log"
            ]:
                continue

            event_id = str(
                item.get("event_id", "")
            )

            text = str(
                item.get("value", "")
            ).lower()

            # High-value forensic events
            if event_id not in ["4103", "4104"]:
                continue

            score = 0

            if event_id == "4104":
                score += 3

            if event_id == "4103":
                score += 2

            indicators = [
                "commandinvocation",
                "creating scriptblock",
                "out-file",
                "get-process",
                "execution",
                "forensic",
                "marker"
            ]

            for indicator in indicators:
                if indicator in text:
                    score += 1

            result = dict(item)
            result["retrieval_score"] = score

            candidates.append(result)

        candidates.sort(
            key=lambda x: x["retrieval_score"],
            reverse=True
        )

        return candidates[:12]

    # ---------------------------------------------------------
    # Security Event 4688
    # ---------------------------------------------------------
    if tool_name == "security_event_search":

        return search(
            memory,
            ["cmd.exe", "4688"],
            ["Windows Security Process Creation"],
            limit=10
        )

    # ---------------------------------------------------------
    # Windows Prefetch
    # ---------------------------------------------------------
    if tool_name == "prefetch_search":

        return search(
            memory,
            ["cmd.exe"],
            ["Windows Prefetch"],
            limit=10
        )

    # ---------------------------------------------------------
    # USBSTOR
    # ---------------------------------------------------------
    if tool_name == "usbstor_search":

        return [
            x for x in memory
            if x.get("artifact_type")
            == "USBSTOR Registry"
        ][:10]

    # ---------------------------------------------------------
    # MountedDevices
    # ---------------------------------------------------------
    if tool_name == "mounted_device_search":

        return [
            x for x in memory
            if x.get("artifact_type")
            == "MountedDevices Registry"
        ][:10]

    # ---------------------------------------------------------
    # Registry persistence
    # ---------------------------------------------------------
    if tool_name == "registry_search":

        return [
            x for x in memory
            if x.get("artifact_type")
            == "Registry Run Key"
        ][:10]

    # ---------------------------------------------------------
    # File-system evidence
    # ---------------------------------------------------------
    if tool_name == "filesystem_search":

        return [
            x for x in memory
            if (
                "File" in x.get("artifact_type", "")
                or
                "Marker" in x.get("artifact_type", "")
                or
                "Script" in x.get("artifact_type", "")
            )
        ][:10]

    return []