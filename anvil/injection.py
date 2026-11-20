"""Prompt-injection scanning for text a server hands to a model.

Two places carry server-controlled text into a model's context: tool descriptions
(``tools/list``) and tool results (``tools/call``). Either can try to give the model
orders. This module scores text from 0 to 100 by adding up the weights of the
signals it finds. Each signal counts once however often it appears.

The scanner is a set of heuristics. It catches the common shapes of an injection and
it can be evaded by someone who studies it. Treat it as one layer next to the policy,
pinning and human approval, not as a guarantee.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any, Iterator

_RULES: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    (
        "instruction-override",
        60,
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
            r"\b(?:all|any|previous|prior|above|earlier|preceding|your)\b[^.\n]{0,30}?"
            r"\b(?:instructions?|prompts?|rules|guidelines|directions|context)\b"
            r"|\b(?:ignore|disregard|forget)\s+(?:everything|anything|all)\b[^.\n]{0,20}?"
            r"\b(?:above|before|previously|said|told)\b"
        ),
    ),
    (
        "role-spoofing",
        45,
        re.compile(
            r"(?i)<\|im_(?:start|end)\|>|\[/?INST\]|<<SYS>>"
            r"|</?\s*(?:system|assistant|human|user)(?:[_ -](?:prompt|message|instructions?))?\s*>"
        ),
    ),
    (
        "role-prefix",
        30,
        re.compile(r"(?im)^\s*(?:#{1,3}\s*)?(?:system|assistant|developer)(?:\s+(?:prompt|message|note))?\s*:\s*\S"),
    ),
    (
        "new-instructions",
        35,
        re.compile(
            r"(?i)\b(?:new|updated|revised|real|actual|important)\s+"
            r"(?:instructions?|task|objective|system prompt)\b\s*[:\-]"
        ),
    ),
    (
        "concealment",
        50,
        re.compile(
            r"(?i)\b(?:do not|don't|dont|never|without)\s+"
            r"(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|reveal(?:ing)?|notify(?:ing)?|alert(?:ing)?|show(?:ing)?)\b"
            r"[^.\n]{0,30}?\b(?:user|human|operator|owner)\b"
        ),
    ),
    (
        "exfiltration",
        45,
        re.compile(
            r"(?i)\b(?:send|post|upload|forward|exfiltrate|transmit|email|leak)\b[^.\n]{0,80}?"
            r"\b(?:to|at|via)\s+(?:https?://\S+|[\w.+-]+@[\w-]+\.[\w.-]+)"
        ),
    ),
    (
        "markdown-exfiltration",
        40,
        re.compile(r"!\[[^\]]{0,200}\]\(\s*https?://[^)\s]{1,300}[?&][^)\s=]{1,50}="),
    ),
    (
        "tool-coercion",
        35,
        re.compile(
            r"(?i)\b(?:you must|you should|always|first|"
            r"before (?:answering|responding|replying|doing anything|using any other tool))\b"
            r"[^.\n]{0,60}?\b(?:call|invoke|run|execute)\b[^.\n]{0,40}?\b(?:tool|function|command)\b"
        ),
    ),
    (
        "credential-access",
        45,
        re.compile(
            r"(?i)\b(?:read|cat|open|fetch|include|print|dump|copy|attach)\b[^.\n]{0,50}?"
            r"(?:~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|/etc/(?:passwd|shadow)"
            r"|\.env\b|\bapi[ _-]?keys?\b|\bpasswords?\b|\bprivate keys?\b)"
        ),
    ),
)

_HTML_COMMENT = re.compile(r"<!--(.{0,2000}?)-->", re.S)
_COMMENT_WORDS = re.compile(r"(?i)\b(?:ignore|instructions?|system|assistant|tool|must|secret|do not|don't)\b")
_ZERO_WIDTH = re.compile("[​‌⁠﻿]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_TAGS = re.compile("[\U000e0000-\U000e007f]")
_BASE64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

MAX_SCAN_CHARS = 200_000


@dataclass(frozen=True)
class Signal:
    name: str
    weight: int
    excerpt: str


@dataclass(frozen=True)
class Report:
    score: int
    signals: tuple[Signal, ...] = ()

    @property
    def names(self) -> list[str]:
        return [signal.name for signal in self.signals]


CLEAN = Report(0)


def scan(text: str) -> Report:
    """Score one piece of text."""
    return _scan(text, decode=True)


def scan_value(value: Any) -> Report:
    """Score every string inside a JSON value and return the worst report."""
    worst = CLEAN
    for text in _strings(value):
        report = scan(text)
        if report.score > worst.score:
            worst = report
    return worst


def scan_tool(tool: dict[str, Any]) -> Report:
    """Score the parts of a tool definition a model reads: its description and schema."""
    return scan_value({"description": tool.get("description"), "inputSchema": tool.get("inputSchema")})


def _scan(text: str, *, decode: bool) -> Report:
    if not text:
        return CLEAN
    text = text[:MAX_SCAN_CHARS]
    signals: list[Signal] = []

    for name, weight, pattern in _RULES:
        match = pattern.search(text)
        if match:
            signals.append(Signal(name, weight, _excerpt(match.group(0))))

    for match in _HTML_COMMENT.finditer(text):
        if _COMMENT_WORDS.search(match.group(1)):
            signals.append(Signal("hidden-comment", 35, _excerpt(match.group(0))))
            break

    # A leading byte order mark is ordinary; anything after that is not.
    if len(_ZERO_WIDTH.findall(text[1:] if text.startswith("﻿") else text)) >= 3:
        signals.append(Signal("invisible-text", 35, "zero-width characters"))
    if _BIDI.search(text):
        signals.append(Signal("bidi-override", 40, "bidirectional control characters"))
    tags = _TAGS.findall(text)
    if tags:
        hidden = "".join(chr(ord(ch) - 0xE0000) for ch in tags if 0xE0020 <= ord(ch) <= 0xE007E)
        signals.append(Signal("unicode-tags", 70, _excerpt(hidden) or "tag characters"))

    if decode:
        for match in _BASE64.finditer(text):
            decoded = _decode(match.group(0))
            if decoded and _scan(decoded, decode=False).score >= 25:
                signals.append(Signal("encoded-instructions", 50, _excerpt(decoded)))
                break

    if not signals:
        return CLEAN
    return Report(min(100, sum(signal.weight for signal in signals)), tuple(signals))


def _decode(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return text if text and printable / len(text) >= 0.9 else None


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)


def _excerpt(text: str, limit: int = 80) -> str:
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text).strip()
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"
