"""Tool pinning: notice when a tool's definition changes after it was first seen.

A server can describe a tool one way when you approve it and another way later. The
gateway fingerprints each tool definition the first time it appears and stores the
fingerprint in a lock file. If a later ``tools/list`` shows a different definition
under the same name, the tool is quarantined until someone re-pins it.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PINNED = "pinned"
NEW = "new"
CHANGED = "changed"

_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def fingerprint(tool: dict[str, Any]) -> str:
    """SHA-256 over the parts of a tool definition that a model or client acts on."""
    material = {key: tool[key] for key in _FIELDS if key in tool}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class PinStore:
    """Fingerprints by tool name, kept in memory and optionally in a lock file."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._tools: dict[str, dict[str, str]] = {}
        if self.path and self.path.exists():
            self._load()

    def status(self, tool: dict[str, Any]) -> str:
        entry = self._tools.get(str(tool.get("name")))
        if entry is None:
            return NEW
        return PINNED if entry["sha256"] == fingerprint(tool) else CHANGED

    def pin(self, tool: dict[str, Any]) -> None:
        """Record (or replace) the fingerprint for this tool and save."""
        self._tools[str(tool.get("name"))] = {
            "sha256": fingerprint(tool),
            "pinned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self._save()

    def forget(self, name: str) -> bool:
        """Drop a pin so the next definition seen under this name is treated as new."""
        if name not in self._tools:
            return False
        del self._tools[name]
        self._save()
        return True

    def names(self) -> list[str]:
        return sorted(self._tools)

    def entry(self, name: str) -> dict[str, str] | None:
        return self._tools.get(name)

    def _load(self) -> None:
        assert self.path is not None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            tools = data["tools"]
            if not isinstance(tools, dict) or not all(
                isinstance(entry, dict) and isinstance(entry.get("sha256"), str) for entry in tools.values()
            ):
                raise ValueError("unexpected shape")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"lock file {self.path} is unreadable: {exc}") from exc
        self._tools = tools

    def _save(self) -> None:
        if self.path is None:
            return
        payload = json.dumps({"version": 1, "tools": self._tools}, indent=2, sort_keys=True) + "\n"
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True)
        # Write beside the target and swap, so a crash never leaves half a lock file.
        handle, temp_name = tempfile.mkstemp(dir=directory, prefix=self.path.name, suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(payload)
            os.replace(temp_name, self.path)
        except BaseException:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise
