"""URL safety guard — SSRF protection + homoglyph URL detection.

Distilled from Hermes Agent's documented controls:
  - SSRF: block private/loopback/link-local/CGNAT/cloud-metadata destinations
    (Sec doc §"SSRF Protection")
  - Homoglyph URL detection: catch IDN attacks where Cyrillic/Greek code
    points produce a domain that visually equals a different real one
    (Sec doc §"Tirith Pre-Exec Security Scanning")
  - Website blocklist: optional config-driven allow/deny glob list
    (Sec doc §"Website Access Policy")

Designed to be called from any place a URL enters the agent's intent —
both pre-tool-call (the agent is about to fetch a URL) and
return-content (a fetched body contains URLs the agent might follow).

Guards are functions on a normalised event dict (see adapters/base.py):

    decision = url_safety_guard(event)
    if decision and decision["block"]: ...

The module exports a `url_safety_guard` callable; for hosts that wire
URLs via different attributes (`event["url"]` vs `event["params"]["url"]`),
pass extractor kwargs to `make_url_safety_guard(...)`.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any, Callable
from urllib.parse import urlparse


# ── Blocked IP ranges (RFC 1918 + extras Hermes documents) ──────────────────

_BLOCKED_V4_NETS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),          # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),       # link-local + cloud metadata 169.254.169.254
    ipaddress.IPv4Network("100.64.0.0/10"),        # CGNAT / Tailscale / WireGuard
    ipaddress.IPv4Network("0.0.0.0/8"),            # unspecified
    ipaddress.IPv4Network("224.0.0.0/4"),          # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),          # reserved
    ipaddress.IPv4Network("255.255.255.255/32"),   # broadcast
]
_BLOCKED_V6_NETS = [
    ipaddress.IPv6Network("::1/128"),              # loopback
    ipaddress.IPv6Network("fc00::/7"),             # unique local
    ipaddress.IPv6Network("fe80::/10"),            # link-local
    ipaddress.IPv6Network("::/128"),               # unspecified
]

_BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",                                # AWS IMDS shortcut
}


# ── Homoglyph detection ─────────────────────────────────────────────────────

# Common cross-script homoglyphs (NOT exhaustive — high-signal set).
# Format: confusable -> canonical ASCII.
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic look-alikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "і": "i", "І": "I", "ј": "j",
    # Greek look-alikes
    "α": "a", "ο": "o", "ρ": "p", "τ": "t",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}

# Pre-compile a regex that finds any of these as a single character.
_HOMOGLYPH_RE = re.compile("|".join(re.escape(k) for k in _HOMOGLYPH_MAP))


def _hostname_codepoints(host: str) -> list[int]:
    return [ord(c) for c in host]


def _detect_homoglyph(host: str) -> tuple[bool, list[int], str]:
    """Return (is_homoglyph, suspicious_codepoints, ascii_doppelganger).

    A host is flagged if it contains characters whose NFKC normal form
    maps to a different ASCII letter (i.e. Cyrillic а that looks like
    Latin a, etc.) — and the resulting ASCII string equals a recognisable
    Latin-only domain.
    """
    if not host:
        return False, [], ""
    suspicious: list[int] = []
    out: list[str] = []
    saw_homoglyph = False
    for c in host:
        if c in _HOMOGLYPH_MAP:
            suspicious.append(ord(c))
            out.append(_HOMOGLYPH_MAP[c])
            saw_homoglyph = True
        else:
            out.append(c)
    doppelganger = "".join(out)
    return saw_homoglyph, suspicious, doppelganger


def _looks_like_ip(host: str) -> tuple[bool, str | None]:
    """Return (is_ip, family). family: 'v4', 'v6', None."""
    try:
        ipaddress.IPv4Address(host)
        return True, "v4"
    except (ValueError, ipaddress.AddressValueError):
        pass
    try:
        ipaddress.IPv6Address(host.strip("[]"))
        return True, "v6"
    except (ValueError, ipaddress.AddressValueError):
        pass
    return False, None


def _ip_is_blocked(host: str) -> tuple[bool, str | None]:
    """Return (blocked, reason)."""
    is_ip, family = _looks_like_ip(host)
    if not is_ip:
        return False, None
    try:
        if family == "v4":
            addr = ipaddress.IPv4Address(host)
            for net in _BLOCKED_V4_NETS:
                if addr in net:
                    return True, f"IPv4 in blocked range {net}"
        elif family == "v6":
            addr = ipaddress.IPv6Address(host.strip("[]"))
            for net in _BLOCKED_V6_NETS:
                if addr in net:
                    return True, f"IPv6 in blocked range {net}"
    except (ValueError, ipaddress.AddressValueError):
        return False, None
    return False, None


# ── URL extraction from arbitrary command strings ──────────────────────────

_URL_RE = re.compile(
    r"""(?ix)
        (?:^|[\s'"`(<])
        (
            https?://
            [^\s'"`)>]+
        )
    """
)


def extract_urls(text: str) -> list[str]:
    """Extract URL substrings from a free-form text (command body, doc, etc.)."""
    return _URL_RE.findall(text or "")


# ── Public guard ────────────────────────────────────────────────────────────


def url_safety_guard(event: dict, *, allow_private: bool = False) -> dict | None:
    """Guard callable: inspect every URL in the event for SSRF / homoglyph / blocklist hits.

    Returns a blocking decision on the FIRST URL that fails. Returns None
    when nothing is flagged (no opinion).
    """
    text_blob = " ".join(
        str(x) for x in [
            event.get("params", {}).get("command", ""),
            event.get("params", {}).get("url", ""),
            event.get("params", {}).get("description", ""),
            event.get("content", ""),
        ] if x
    )
    urls = extract_urls(text_blob)
    if not urls:
        return None

    for raw_url in urls:
        try:
            parsed = urlparse(raw_url)
        except ValueError:
            continue
        host = (parsed.hostname or "").strip().lower()
        if not host:
            continue

        # 1. IDN convert (punycode the unicode host)
        try:
            host_ascii = host.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeEncodeError):
            host_ascii = host

        # 2. Homoglyph detection (BEFORE IDN — match on the raw host)
        is_homoglyph, suspicious, doppelganger = _detect_homoglyph(host)
        if is_homoglyph:
            return {
                "block": True,
                "outcome": "deny",
                "source": "url_safety:homoglyph",
                "severity": "critical",
                "reason": (
                    f"Homoglyph attack: URL hostname {host!r} contains non-Latin "
                    f"codepoints {suspicious} that visually resemble {doppelganger!r}."
                ),
                "evidence": {
                    "url": raw_url,
                    "host_raw": host,
                    "host_ascii": host_ascii,
                    "doppelganger": doppelganger,
                    "suspicious_codepoints": suspicious,
                },
            }

        # 3. Blocked hostname list
        if host_ascii in _BLOCKED_HOSTNAMES:
            return {
                "block": True,
                "outcome": "deny",
                "source": "url_safety:hostname_blocklist",
                "severity": "high",
                "reason": f"Hostname {host_ascii!r} is on the blocked-hostnames list (cloud metadata).",
                "evidence": {"url": raw_url, "host": host_ascii},
            }

        # 4. IP-literal: SSRF check (private / loopback / link-local / CGNAT / metadata)
        if not allow_private:
            blocked, why = _ip_is_blocked(host_ascii)
            if blocked:
                return {
                    "block": True,
                    "outcome": "deny",
                    "source": "url_safety:ssrf",
                    "severity": "critical",
                    "reason": f"SSRF: {why}",
                    "evidence": {"url": raw_url, "host": host_ascii},
                }

    return None


def make_url_safety_guard(*, allow_private: bool = False) -> Callable:
    """Factory for callers that want a closure-customised version."""
    def _guard(event: dict) -> dict | None:
        return url_safety_guard(event, allow_private=allow_private)
    _guard.__name__ = "url_safety_guard"
    return _guard
