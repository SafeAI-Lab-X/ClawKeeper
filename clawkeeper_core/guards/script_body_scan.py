"""Sensitive-path heuristic over shared, bounded execution facts.

Python retains the proximity heuristic for dynamically assembled paths. Its
file-operation evidence must be a parsed call; proven output data, comments and
standalone literals are excluded. Shell checks use individual invocation facts.
This does not attempt arbitrary Python data-flow analysis.
"""

from __future__ import annotations

from clawkeeper_core.execution import analysis_scope, analyze_event
from clawkeeper_core.learned_rules import match_learned

# Markers for sensitive directories / files. Case-insensitive matched.
_SENSITIVE_DIR_MARKERS = [
    ".aws/credentials",
    ".aws/config",
    ".ssh/id_",
    ".ssh/authorized_keys",
    ".gnupg/",
    ".aws",          # quoted-string-split case: Path.home()/'.aws'/'credentials'
    ".ssh",
    ".gnupg",
    ".kube",
    ".kube/config",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/passwd",
    ".docker/config.json",
    ".pypirc",
    ".netrc",
    # Less specific but still useful when paired with a file-op marker:
    ".aws/",
    ".ssh/",
    ".gnupg",
]

# Markers for file-open / read primitives. Case-sensitive (Python syntax).
_FILE_OP_MARKERS = [
    "Path.home",
    "Path(",
    "expanduser",
    "expandvars",
    "os.environ['HOME']",
    'os.environ["HOME"]',
    ".read_text",
    ".read_bytes",
    "open(",
    "with open ",
    ".read(",
    "configparser",
    "RawConfigParser",
    "ConfigParser",
    "json.load",
    "yaml.safe_load",
    "tomllib.load",
    # Shell-side primitives
    "cat ",
    "head ",
    "tail ",
    "less ",
    "more ",
    "xxd ",
    "od ",
    "base64 ",
]

_PROXIMITY = 500  # chars between the two markers — empirical


def _find_first(text: str, needles, *, lower: bool = False) -> tuple[int, str] | None:
    """Return the first (offset, marker) match, or None."""
    haystack = text.lower() if lower else text
    for n in needles:
        idx = haystack.find(n.lower() if lower else n)
        if idx >= 0:
            return idx, n
    return None


def _find_all(text: str, needles, *, lower: bool = False) -> list[tuple[int, str]]:
    haystack = text.lower() if lower else text
    out: list[tuple[int, str]] = []
    for n in needles:
        cur = 0
        n_normed = n.lower() if lower else n
        while True:
            idx = haystack.find(n_normed, cur)
            if idx < 0:
                break
            out.append((idx, n))
            cur = idx + len(n_normed)
    out.sort()
    return out


def _scan(text: str, operations: list[tuple[int, str]]) -> dict | None:
    dir_hits = _find_all(text, _SENSITIVE_DIR_MARKERS, lower=True)
    if not dir_hits or not operations:
        return None
    distance, d_marker, o_marker = min(
        (abs(d_off - o_off), d_marker, o_marker)
        for d_off, d_marker in dir_hits for o_off, o_marker in operations
    )
    if distance > _PROXIMITY:
        return None
    return {
        "block": True,
        "outcome": "deny",
        "source": "script_body_scan:co_occurrence",
        "severity": "high",
        "reason": (f"Sensitive marker {d_marker!r} near parsed file operation "
                   f"{o_marker!r} ({distance} chars apart)"),
        "evidence": {
            "sensitive_markers": sorted({m for _, m in dir_hits})[:5],
            "file_op_markers": sorted({m for _, m in operations})[:5],
            "min_distance_chars": distance,
        },
    }


def _python_operations(calls, text):
    operations = []
    data = text.encode()
    for call in calls:
        if call.kind != "python.operation":
            continue
        name = call.executable.removeprefix("python:")
        base = len(data[:call.origin.start].decode())
        for marker in _FILE_OP_MARKERS:
            operation = marker.strip().removesuffix("(")
            if (name == operation or name.endswith("." + operation)
                    or (operation.startswith(".") and name.endswith(operation))
                    or name.startswith(operation + ".")):
                operations.append((base, marker))
    return operations


@analysis_scope()
def script_body_scan_guard(event: dict) -> dict | None:
    learned = match_learned("script_body_scan", event)
    if learned is not None:
        return learned
    facts = analyze_event(event)
    if not facts.complete:
        return {"block": True, "outcome": "ask", "source": "script_body_scan:analysis",
                "reason": "Execution context analysis incomplete", "analysis": "indeterminate"}
    for source_id, source in enumerate(facts.sources):
        calls = [c for c in facts.calls if c.origin.source == source_id]
        if source.language == "python":
            data = bytearray(source.text.encode())
            for span in facts.data:
                if span.origin.source == source_id:
                    data[span.origin.start:span.origin.end] = b" " * (span.origin.end - span.origin.start)
            text = data.decode()
            result = _scan(text, _python_operations(calls, text))
            if result:
                result["evidence"]["source_id"] = source_id
                return result
        else:
            for call in calls:
                text = call.render(learned=True)
                operations = [(0, marker) for marker in _FILE_OP_MARKERS
                              if marker == call.executable + " "]
                result = _scan(text, operations)
                if result:
                    return result
    return None
