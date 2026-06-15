"""08.a — Authorization bypass at gateway adapter layer.

STATUS: documented stub. CVE-2026-7396 is the known PoC; replicating it
locally requires standing up the WeChat platform adapter (or its
equivalent in a generic adapter) and feeding crafted user IDs — out of
scope for the agent-side smoke test. Documented for Task 2.

Threat class: authorization_bypass_gateway

Variants:

  08.a (path traversal in adapter): CVE-2026-7396 — the WeChat Work
        platform adapter mishandled user-supplied paths, allowing a
        remote attacker to read unauthorized files via the messaging
        gateway. Fixed in Hermes 0.9.0 (presumably). The lesson: every
        platform adapter is a fresh authz surface; the gateway-level
        allowlist doesn't reach inside individual adapter request
        handlers.

  08.b (Unicode normalisation): DISCORD_ALLOWED_USERS=908352645507477514
        — does an attacker who pastes 9‌08352645507477514 (with a zero-
        width non-joiner U+200C between digits) bypass the comparison?
        The allowlist parser uses str.strip().split(',') and exact
        equality, which Unicode-NFC-normalises NOT done — so the
        zero-width form is treated as a different ID. But the agent
        may also accept by-handle resolution which falls back to
        username matching... need to verify.

Defense layers (Hermes): pairing system has good lockout; adapter-level
authz is each adapter's problem.

Task 2 implication: a small `clawkeeper_core.guards.gateway_input`
module that normalises and validates user IDs / channel IDs at the
gateway intake boundary, independent of any per-adapter logic.
"""
from __future__ import annotations


SCENARIO = {
    "id": "08.a",
    "name": "Gateway authz bypass — adapter path traversal class (CVE-2026-7396)",
    "threat_class": "authorization_bypass_gateway",
    "entry_vector": "Crafted user-ID / path in messaging adapter request handler",
    "trajectory": [
        "Send crafted request to WeChat (or any) platform adapter",
        "Adapter mishandles path normalisation",
        "Attacker reads unauthorized file via the messaging endpoint",
    ],
    "success_criterion": "Adapter returns a file the user shouldn't have been able to reach.",
    "expected_defense_layers": {
        "hermes_user_authz": "yes for documented allowlist; adapter-level handlers vary",
        "clawkeeper_gateway_input": "GAP — to build in Task 2",
    },
    "citation": "CVE-2026-7396 (WeChat Work platform adapter, Hermes <0.9.0)",
    "runnable": False,
}
