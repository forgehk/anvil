"""Append-only audit log with a hash chain.

Each line is one JSON record. A record carries the hash of the record before it and
its own hash, so editing, deleting or reordering any earlier line breaks every hash
that follows. ``verify`` walks the file and reports the first line that does not fit.

The chain shows tampering by someone who can edit the file but cannot also recompute
and rewrite every later hash. For stronger guarantees, ship the log off the machine.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

GENESIS = "0" * 64


def _digest(previous: str, body: dict[str, Any]) -> str:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((previous + encoded).encode("utf-8")).hexdigest()


class AuditLog:
    """Writes records to ``path``. With no path, records are kept in memory only."""

    def __init__(self, path: str | Path | None = None, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path) if path else None
        self._clock = clock
        self._lock = threading.Lock()
        self._previous = GENESIS
        self._seq = 0
        self.records: list[dict[str, Any]] = []
        if self.path and self.path.exists():
            self._resume()

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        """Add a record and return it. Safe to call from several threads."""
        with self._lock:
            self._seq += 1
            body = {"seq": self._seq, "ts": round(self._clock(), 3), "event": event, **fields, "prev": self._previous}
            record = {**body, "hash": _digest(self._previous, body)}
            self._previous = record["hash"]
            if self.path is None:
                self.records.append(record)
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
            return record

    def _resume(self) -> None:
        assert self.path is not None
        last = None
        with self.path.open("r", encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    last = line
        if last is None:
            return
        try:
            record = json.loads(last)
            self._previous = record["hash"]
            self._seq = int(record["seq"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"audit log {self.path} ends in a line that is not a record") from exc


@dataclass(frozen=True)
class Verification:
    ok: bool
    records: int
    line: int | None = None
    problem: str = ""


def verify(path: str | Path) -> Verification:
    """Check every record in the log against the chain."""
    previous = GENESIS
    expected_seq = 0
    count = 0
    with Path(path).open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                return Verification(False, count, number, "line is not valid JSON")
            if not isinstance(record, dict) or "hash" not in record or "prev" not in record:
                return Verification(False, count, number, "line is not an audit record")
            expected_seq += 1
            if record.get("seq") != expected_seq:
                return Verification(False, count, number, f"expected seq {expected_seq}, found {record.get('seq')}")
            if record["prev"] != previous:
                return Verification(False, count, number, "record does not follow the one before it")
            body = {key: value for key, value in record.items() if key != "hash"}
            if _digest(previous, body) != record["hash"]:
                return Verification(False, count, number, "record was modified after it was written")
            previous = record["hash"]
            count += 1
    return Verification(True, count)
