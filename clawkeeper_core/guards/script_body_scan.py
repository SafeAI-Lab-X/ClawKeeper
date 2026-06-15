"""Script-body scanner — heuristic detection of sensitive operations
inside shell or Python scripts where literal-path regex fails.

Closes the gap path_guard cannot:  dynamic path construction via
`Path.home() / '.aws' / 'credentials'`, `os.path.expanduser('~/.ssh/...')`,
or runtime string assembly that never produces a single literal sensitive
path token.  Surfaced concretely by red-team scenario 07.a re-run:
the agent split `'.aws'` and `'credentials'` across `Path()` operands
and successfully read `/root/.aws/credentials` via `RawConfigParser.read()`.

Intentionally heuristic and substring-based:  not a full AST parser.
Trade-off — minor false positives (a benign script that mentions
`~/.aws` in a docstring AND happens to call `open()`) for catching the
cases real adversaries actually use.

Reduce false positives via two rules:
  1.  Both a sensitive-dir marker AND a file-op primitive must appear in
      the same `command` string.
  2.  The two markers must be close-ish (≤500 chars between them) so a
      coincidental co-occurrence in unrelated parts of a large script
      doesn't fire.
"""

from __future__ import annotations

from typing import Optional

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


def _find_first(text: str, needles, *, lower: bool = False) -> Optional[tuple[int, str]]:
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


def script_body_scan_guard(event: dict) -> Optional[dict]:
    """Block when a command body contains BOTH a sensitive-dir marker AND a
    file-read primitive within `_PROXIMITY` chars of each other.
    """
    cmd = (event.get("params") or {}).get("command", "") or ""
    if not cmd:
        return None

    dir_hits = _find_all(cmd, _SENSITIVE_DIR_MARKERS, lower=True)
    if not dir_hits:
        return None

    op_hits = _find_all(cmd, _FILE_OP_MARKERS, lower=False)
    if not op_hits:
        return None

    # Find a close pair.
    closest_pair = None
    closest_dist = None
    for d_off, d_marker in dir_hits:
        for o_off, o_marker in op_hits:
            dist = abs(d_off - o_off)
            if closest_dist is None or dist < closest_dist:
                closest_dist = dist
                closest_pair = (d_marker, o_marker, dist)

    if closest_pair is None or closest_dist is None:
        return None
    if closest_dist > _PROXIMITY:
        return None

    d_marker, o_marker, dist = closest_pair
    return {
        "block": True,
        "outcome": "deny",
        "source": "script_body_scan:co_occurrence",
        "severity": "high",
        "reason": (
            f"Script body references sensitive marker {d_marker!r} alongside "
            f"file-op primitive {o_marker!r} ({dist} chars apart); likely "
            "credential/secret access via dynamic path construction."
        ),
        "evidence": {
            "sensitive_markers": list({m for _, m in dir_hits})[:5],
            "file_op_markers": list({m for _, m in op_hits})[:5],
            "min_distance_chars": dist,
        },
    }
