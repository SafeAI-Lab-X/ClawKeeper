"""Intent extraction + tool-chain drift detection.

Ported from legacy/clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/intent-drift.js.
Behavior parity is verified by tests/test_drift.py.

The detector compares the user's stated intent (first non-empty user message)
against the actual tool chain observed afterwards, and emits a drift score on
[0, 1] derived from:

    - topic divergence (tokens in intent vs. tokens touched by tools)
    - verb-category mismatch (e.g. user asked to "read" but tools "execute")
    - sensitive-target hits (SSH keys, /etc/passwd, persistence files, …)
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, TypedDict

DEFAULT_THRESHOLD = 0.4


# ── Constants ───────────────────────────────────────────────────────────────


VERB_CATEGORIES: dict[str, list[str]] = {
    "create": [
        "write", "create", "build", "generate", "make", "add",
        "implement", "develop", "scaffold", "写", "创建",
    ],
    "read": [
        "read", "show", "display", "list", "find", "search", "look",
        "check", "view", "get", "print", "读取", "查看",
    ],
    "modify": [
        "edit", "update", "change", "modify", "refactor", "rename",
        "replace", "fix", "patch", "修改", "编辑",
    ],
    "delete": [
        "delete", "remove", "drop", "clean", "purge", "clear",
        "uninstall", "删除",
    ],
    "execute": [
        "run", "execute", "start", "launch", "deploy", "install",
        "test", "debug", "compile", "运行", "执行",
    ],
    "network": [
        "download", "upload", "fetch", "curl", "request", "send",
        "post", "push", "pull", "clone",
    ],
    "analyze": [
        "analyze", "explain", "summarize", "review", "compare",
        "audit", "inspect", "diagnose", "help", "分析", "帮我",
    ],
}


STOPWORDS: set[str] = {
    "a", "an", "and", "are", "for", "from", "i", "in", "into", "is",
    "it", "me", "my", "of", "on", "or", "please", "the", "this", "to",
    "with",
    "一下", "这个", "那个", "请", "把", "并", "然后", "一个", "现在",
    "需要", "想要", "帮", "我", "你", "他",
}


class _SensitivePattern(TypedDict):
    id: str
    label: str
    pattern: re.Pattern[str]


SENSITIVE_TOPIC_PATTERNS: list[_SensitivePattern] = [
    {"id": "ssh_keys", "label": "SSH keys",
     "pattern": re.compile(r"(?:^|/)\.ssh/|id_rsa|id_ed25519|authorized_keys", re.IGNORECASE)},
    {"id": "cloud_creds", "label": "Cloud credentials",
     "pattern": re.compile(r"(?:^|/)\.aws/|credentials|(?:^|/)\.env(?:\.|$)?", re.IGNORECASE)},
    {"id": "system_creds", "label": "System credentials",
     "pattern": re.compile(r"/etc/passwd|/etc/shadow|/etc/sudoers", re.IGNORECASE)},
    {"id": "crypto_keys", "label": "Crypto keys",
     "pattern": re.compile(r"(?:^|/)\.gnupg|private_key", re.IGNORECASE)},
    {"id": "exfiltration", "label": "Exfiltration primitives",
     "pattern": re.compile(r"curl\|bash|nc\s+-l|reverse shell", re.IGNORECASE)},
    {"id": "priv_esc", "label": "Privilege escalation",
     "pattern": re.compile(r"\bsudo\b|chmod\s+777|chown\s+root", re.IGNORECASE)},
    {"id": "persistence", "label": "Persistence locations",
     "pattern": re.compile(r"\bcrontab\b|(?:^|/)\.bashrc|(?:^|/)\.zshrc|git hooks", re.IGNORECASE)},
]


# JS `String.matchAll` with /g flag → Python re.finditer.
# Note: JS uses ` (backtick) for quoted strings; we keep it for parity.
_PATH_RE = re.compile(r"""(?:^|[\s(])((?:~|\.{1,2}|/)[^\s"'`<>|)]+)""")
_QUOTED_RE = re.compile(r'''"([^"\n]{2,})"|'([^'\n]{2,})'|`([^`\n]{2,})`''')
_LATIN_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{1,}")
_CJK_TOKEN_RE = re.compile(r"[一-鿿]{2,}")
_CJK_CHAR_RE = re.compile(r"[一-鿿]")


# ── Helpers ────────────────────────────────────────────────────────────────


def _normalize_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _unique_sorted(values: Iterable[str]) -> list[str]:
    return sorted({v for v in values if v})


def _matches_term(text: str, term: str) -> bool:
    """Locale-aware term match: CJK uses substring; Latin uses word boundary."""
    if not text or not term:
        return False
    if _CJK_CHAR_RE.search(term):
        return term in text
    escaped = re.escape(term)
    return bool(re.search(rf"\b{escaped}\b", text, re.IGNORECASE))


# ── Public extractors ──────────────────────────────────────────────────────


def extract_paths_from_text(text: Any) -> list[str]:
    source = _normalize_text(text)
    paths: list[str] = []
    for m in _PATH_RE.finditer(source):
        path = (m.group(1) or "").strip()
        if path:
            paths.append(path)
    return _unique_sorted(paths)


def extract_quoted_strings(text: Any) -> list[str]:
    source = _normalize_text(text)
    values: list[str] = []
    for m in _QUOTED_RE.finditer(source):
        value = _normalize_text(m.group(1) or m.group(2) or m.group(3))
        if len(value) >= 2:
            values.append(value)
    return _unique_sorted(values)


def _tokenize_text(text: Any) -> list[str]:
    source = _normalize_text(text)
    tokens: list[str] = []
    for m in _LATIN_TOKEN_RE.finditer(source):
        tokens.append(m.group(0).lower())
    for m in _CJK_TOKEN_RE.finditer(source):
        tokens.append(m.group(0))
    return tokens


def _extract_verb_matches(text: str) -> tuple[list[str], list[str]]:
    source = _normalize_text(text)
    verbs: list[str] = []
    categories: list[str] = []
    for category, terms in VERB_CATEGORIES.items():
        for term in terms:
            if _matches_term(source, term):
                verbs.append(term)
                categories.append(category)
    return _unique_sorted(verbs), _unique_sorted(categories)


def extract_topics_from_text(text: Any, *, include_quoted: bool = True) -> list[str]:
    source = _normalize_text(text)
    if not source:
        return []

    quoted_strings = extract_quoted_strings(source) if include_quoted else []
    quoted_tokens = [_lower(v) for v in quoted_strings if _lower(v)]
    path_tokens = {_lower(p) for p in extract_paths_from_text(source)}
    verb_tokens = {_lower(v) for terms in VERB_CATEGORIES.values() for v in terms if _lower(v)}

    tokens: list[str] = []
    for token in _tokenize_text(source):
        if len(token) < 2:
            continue
        if token in STOPWORDS:
            continue
        if token in verb_tokens:
            continue
        if token in path_tokens:
            continue
        tokens.append(token)

    return _unique_sorted(quoted_tokens + tokens)


def _map_tool_name_to_categories(tool_name: Any) -> list[str]:
    name = _lower(tool_name)
    if not name:
        return []
    categories: list[str] = []
    if re.search(r"(read|grep|glob|find|search|open|cat|list|view)", name):
        categories.append("read")
    if re.search(r"(write|edit|replace|patch|update|rename)", name):
        categories.append("modify")
    if re.search(r"(create|scaffold|generate)", name):
        categories.append("create")
    if re.search(r"(delete|remove|rm|unlink|purge)", name):
        categories.append("delete")
    if re.search(r"(bash|exec|shell|run|test|debug|compile)", name):
        categories.append("execute")
    if re.search(r"(curl|request|fetch|download|upload|clone|post|push|pull)", name):
        categories.append("network")
    if re.search(r"(review|analy|audit|inspect|explain)", name):
        categories.append("analyze")
    return _unique_sorted(categories)


# ── Main API ───────────────────────────────────────────────────────────────


def extract_intent(messages: Any) -> dict[str, Any] | None:
    """Pull the first non-empty user message and decompose it into intent fields.

    Returns None if there is no usable user message (empty list, no user role,
    or content shorter than 3 chars).
    """
    msgs = messages if isinstance(messages, list) else []
    seed = next(
        (m for m in msgs
         if isinstance(m, dict)
         and m.get("role") == "user"
         and _normalize_text(m.get("content"))),
        None,
    )
    raw_intent = _normalize_text(seed.get("content") if seed else "")
    if len(raw_intent) < 3:
        return None

    verbs, verb_categories = _extract_verb_matches(raw_intent)
    return {
        "verbs": verbs,
        "verbCategories": verb_categories,
        "topics": extract_topics_from_text(raw_intent),
        "paths": extract_paths_from_text(raw_intent),
        "quotedStrings": extract_quoted_strings(raw_intent),
        "rawIntent": raw_intent,
    }


def summarize_tool_chain(messages: Any) -> dict[str, Any]:
    """Collapse tool messages into aggregate paths / topics / verb-categories."""
    msgs = messages if isinstance(messages, list) else []
    tools: list[dict[str, Any]] = []
    all_paths: list[str] = []
    all_topics: list[str] = []
    all_verb_categories: list[str] = []
    full_text_parts: list[str] = []

    for m in msgs:
        if not isinstance(m, dict):
            continue
        tool_name = _normalize_text(m.get("toolName") or m.get("name")).lower()
        if not tool_name:
            continue

        text_parts = [
            _normalize_text(m.get("content")),
            _normalize_text(m.get("raw")),
            _normalize_text(m.get("result")),
            _normalize_text(m.get("error")),
        ]
        combined = "\n".join(p for p in text_parts if p)
        paths = extract_paths_from_text(combined)
        topics = extract_topics_from_text(combined)
        verb_categories = _map_tool_name_to_categories(tool_name)

        tools.append({
            "toolName": tool_name,
            "paths": paths,
            "topics": topics,
            "verbCategories": verb_categories,
        })
        all_paths.extend(paths)
        all_topics.extend(topics)
        all_verb_categories.extend(verb_categories)
        full_text_parts.append(tool_name)
        if combined:
            full_text_parts.append(combined)

    return {
        "tools": tools,
        "paths": _unique_sorted(all_paths),
        "topics": _unique_sorted(all_topics),
        "verbCategories": _unique_sorted(all_verb_categories),
        "fullText": "\n".join(p for p in full_text_parts if p),
    }


def _compute_topic_divergence(intent_topics: list[str], tool_topics: list[str]) -> dict[str, Any]:
    intent_set = set(intent_topics)
    tool_set = set(tool_topics)
    if not intent_set:
        return {"overlap": 0, "divergence": 1 if tool_set else 0, "intersection": []}
    intersection = [t for t in intent_set if t in tool_set]
    overlap = len(intersection) / max(len(intent_set), 1)
    return {"overlap": overlap, "divergence": 1 - overlap, "intersection": intersection}


def _compute_verb_mismatch(intent_cats: list[str], observed_cats: list[str]) -> dict[str, Any]:
    intent_set = set(intent_cats)
    observed_set = set(observed_cats)
    if not intent_set or not observed_set:
        return {"mismatch": 0, "matched": [], "unexpected": []}
    matched = [c for c in observed_set if c in intent_set]
    unexpected = [c for c in observed_set if c not in intent_set]
    if matched:
        return {
            "mismatch": len(unexpected) / len(observed_set),
            "matched": matched,
            "unexpected": unexpected,
        }
    return {"mismatch": 1, "matched": [], "unexpected": unexpected}


def _detect_sensitive_hits(tool_chain: dict[str, Any]) -> list[dict[str, str]]:
    searchable = "\n".join([
        tool_chain.get("fullText", ""),
        *tool_chain.get("paths", []),
        *tool_chain.get("topics", []),
    ])
    return [
        {"id": e["id"], "label": e["label"]}
        for e in SENSITIVE_TOPIC_PATTERNS
        if e["pattern"].search(searchable)
    ]


def score_to_drift_severity(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def detect_drift(intent: Any, tool_chain: Any, *, threshold: float = DEFAULT_THRESHOLD) -> dict[str, Any]:
    """Score how much the tool chain has drifted from the user's intent."""
    try:
        thr = max(0.0, min(1.0, float(threshold)))
    except (TypeError, ValueError):
        thr = DEFAULT_THRESHOLD

    intent_d = intent if isinstance(intent, dict) else {}
    chain = tool_chain if isinstance(tool_chain, dict) else {}

    topic = _compute_topic_divergence(intent_d.get("topics") or [], chain.get("topics") or [])
    verb = _compute_verb_mismatch(intent_d.get("verbCategories") or [], chain.get("verbCategories") or [])
    sensitive_hits = _detect_sensitive_hits(chain)
    sensitive_score = min(1.0, len(sensitive_hits) / 2)
    score = min(1.0, 0.3 * topic["divergence"] + 0.3 * verb["mismatch"] + 0.4 * sensitive_score)
    severity = score_to_drift_severity(score)
    detected = score >= thr

    tools = chain.get("tools") or []
    return {
        "detected": detected,
        "score": score,
        "threshold": thr,
        "severity": severity,
        "intent": {
            "rawIntent": intent_d.get("rawIntent") or "",
            "verbCategories": _unique_sorted(intent_d.get("verbCategories") or []),
            "topics": _unique_sorted(intent_d.get("topics") or []),
            "paths": _unique_sorted(intent_d.get("paths") or []),
        },
        "toolChain": {
            "toolCount": len(tools),
            "toolNames": _unique_sorted(t.get("toolName") for t in tools if isinstance(t, dict) and t.get("toolName")),
            "verbCategories": _unique_sorted(chain.get("verbCategories") or []),
            "topics": _unique_sorted(chain.get("topics") or []),
            "paths": _unique_sorted(chain.get("paths") or []),
        },
        "signals": {
            "topicDivergence": topic["divergence"],
            "topicOverlap": topic["overlap"],
            "sharedTopics": _unique_sorted(topic["intersection"]),
            "verbMismatch": verb["mismatch"],
            "matchedVerbCategories": _unique_sorted(verb["matched"]),
            "unexpectedVerbCategories": _unique_sorted(verb["unexpected"]),
            "sensitiveScore": sensitive_score,
        },
        "sensitiveHits": sensitive_hits,
        "warning": (
            f"Current tool chain appears semantically drifted from the user's original intent "
            f"(score={score:.2f}, severity={severity})."
            if detected else None
        ),
    }


def resolve_intent_drift(*, body: Any = None, config: Any = None) -> dict[str, Any] | None:
    """Top-level entry that the watcher pipeline calls.

    Returns the drift report only when drift is *detected* (otherwise None).
    """
    cfg = config if isinstance(config, dict) else {}
    drift_config = cfg.get("intentDrift")
    if not isinstance(drift_config, dict):
        return None
    if not drift_config.get("enabled"):
        return None

    body_d = body if isinstance(body, dict) else {}
    fc = body_d.get("forwardedContext")
    if not isinstance(fc, dict):
        return None
    messages = fc.get("messages")
    if not isinstance(messages, list) or not messages:
        return None

    try:
        threshold = max(0.0, min(1.0, float(drift_config.get("threshold", DEFAULT_THRESHOLD))))
    except (TypeError, ValueError):
        threshold = DEFAULT_THRESHOLD

    intent = extract_intent(messages)
    if not intent:
        return None
    tool_chain = summarize_tool_chain(messages)
    if not tool_chain["tools"]:
        return None
    result = detect_drift(intent, tool_chain, threshold=threshold)
    return result if result["detected"] else None


# ── OO façade matching DESIGN.md surface ────────────────────────────────────


class IntentDrift:
    """Convenience wrapper over the module-level functions."""

    def __init__(self, threshold: float = DEFAULT_THRESHOLD) -> None:
        self.threshold = threshold

    def extract_intent(self, messages: Any) -> dict[str, Any] | None:
        return extract_intent(messages)

    def summarize_tool_chain(self, messages: Any) -> dict[str, Any]:
        return summarize_tool_chain(messages)

    def detect(self, intent: Any, tool_chain: Any, *, threshold: float | None = None) -> dict[str, Any]:
        return detect_drift(
            intent, tool_chain,
            threshold=self.threshold if threshold is None else threshold,
        )

    def resolve(self, *, body: Any = None, config: Any = None) -> dict[str, Any] | None:
        return resolve_intent_drift(body=body, config=config)
