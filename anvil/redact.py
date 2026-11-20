"""Secret redaction for text and JSON that crosses the gateway.

Two kinds of detector run:

* shape detectors, for credentials with a recognizable format (cloud key ids,
  platform tokens, PEM private keys, JWTs);
* an assignment detector, for ``password=...`` style pairs whose value has enough
  entropy to be a real secret and not a placeholder.

Every match is replaced with ``[REDACTED:<kind>]`` so the reader can still tell that
something was there and what sort of thing it was.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S)),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("slack-token", re.compile(r"\bxox[abeprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer-token", re.compile(r"(?i)(?<=\bbearer )[A-Za-z0-9._~+/=-]{20,}")),
    ("url-credentials", re.compile(r"(?<=://)[^\s/:@]+:[^\s/@]{3,}(?=@)")),
)

_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<key>[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_.-]*)
    (?P<sep>["']?\s*[:=]\s*["']?)
    (?P<value>[^\s"',;&]{8,})
    """
)

# Values an assignment detector should leave alone: they are clearly not secrets.
_PLACEHOLDER = re.compile(r"(?i)^(?:x+|\*+|\.+|<[^>]*>|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|changeme|example|none|null|true|false|redacted)$")

MIN_ENTROPY = 3.0


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int


def entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def find(text: str) -> list[Finding]:
    """Locate secrets in ``text``. Findings do not overlap and are sorted by position."""
    found: list[Finding] = []
    for kind, pattern in _SHAPES:
        for match in pattern.finditer(text):
            found.append(Finding(kind, match.start(), match.end()))
    for match in _ASSIGNMENT.finditer(text):
        value = match.group("value")
        if value.startswith("[REDACTED:") or _PLACEHOLDER.match(value) or entropy(value) < MIN_ENTROPY:
            continue
        found.append(Finding("assigned-secret", match.start("value"), match.end("value")))
    return _without_overlaps(found)


def redact(text: str) -> tuple[str, list[Finding]]:
    """Return ``text`` with every secret replaced, plus what was found."""
    findings = find(text)
    if not findings:
        return text, []
    parts: list[str] = []
    cursor = 0
    for finding in findings:
        parts.append(text[cursor:finding.start])
        parts.append(f"[REDACTED:{finding.kind}]")
        cursor = finding.end
    parts.append(text[cursor:])
    return "".join(parts), findings


def redact_value(value: Any) -> tuple[Any, Counter[str]]:
    """Redact every string inside a JSON value. Returns a new value and a count per kind."""
    counts: Counter[str] = Counter()

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            cleaned, findings = redact(node)
            counts.update(f.kind for f in findings)
            return cleaned
        if isinstance(node, list):
            return [walk(item) for item in node]
        if isinstance(node, dict):
            return {key: walk(item) for key, item in node.items()}
        return node

    return walk(value), counts


def _without_overlaps(findings: list[Finding]) -> list[Finding]:
    # Earliest start first; on a tie the longer match wins. Later overlapping matches are dropped.
    ordered = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    kept: list[Finding] = []
    for finding in ordered:
        if kept and finding.start < kept[-1].end:
            continue
        kept.append(finding)
    return kept
