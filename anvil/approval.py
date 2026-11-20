"""Human approval for calls the policy marks ``approve``.

The gateway speaks the protocol over its own stdin and stdout, so it cannot ask there.
``TtyApprover`` opens the controlling terminal directly. If there is no terminal, or
nobody answers in time, the call is denied: approval fails closed.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Callable, Protocol


@dataclass(frozen=True)
class ApprovalRequest:
    tool: str
    arguments: dict[str, Any]
    reason: str


class Approver(Protocol):
    def decide(self, request: ApprovalRequest) -> bool: ...


class DenyAll:
    """Refuse everything. The safe choice when no human is available."""

    def decide(self, request: ApprovalRequest) -> bool:
        return False


class CallbackApprover:
    """Delegate the decision to a function. Used by tests and by embedding programs."""

    def __init__(self, callback: Callable[[ApprovalRequest], bool]) -> None:
        self._callback = callback

    def decide(self, request: ApprovalRequest) -> bool:
        return bool(self._callback(request))


class TtyApprover:
    """Ask on the controlling terminal and wait up to ``timeout`` seconds for y or n."""

    def __init__(self, timeout: float = 60.0) -> None:
        self.timeout = timeout
        self._lock = threading.Lock()

    def decide(self, request: ApprovalRequest) -> bool:
        # One question at a time, so two prompts never interleave on the terminal.
        with self._lock:
            try:
                reader, writer = _open_terminal()
            except OSError:
                return False
            answer: list[str] = []

            def ask() -> None:
                try:
                    writer.write(_render(request))
                    writer.flush()
                    answer.append(reader.readline())
                except (OSError, ValueError):
                    pass

            # The read happens on a helper thread so the timeout holds on every platform.
            thread = threading.Thread(target=ask, daemon=True)
            thread.start()
            thread.join(self.timeout)
            timed_out = thread.is_alive()
            try:
                if timed_out:
                    writer.write("\n[anvil] no answer in time, denied\n")
                    writer.flush()
            except (OSError, ValueError):
                pass
            if timed_out or not answer:
                return False
            return answer[0].strip().lower() in ("y", "yes")


def _open_terminal():
    if os.name == "nt":
        return open("CONIN$", "r", encoding="utf-8"), open("CONOUT$", "w", encoding="utf-8")
    return open("/dev/tty", "r", encoding="utf-8"), open("/dev/tty", "w", encoding="utf-8")


def _render(request: ApprovalRequest) -> str:
    arguments = json.dumps(request.arguments, indent=2, sort_keys=True, ensure_ascii=False)
    if len(arguments) > 2000:
        arguments = arguments[:2000] + "\n… (truncated)"
    return (
        "\n[anvil] approval needed\n"
        f"  tool:   {request.tool}\n"
        f"  why:    {request.reason}\n"
        f"  args:   {arguments.replace(chr(10), chr(10) + '          ')}\n"
        "Allow this call? [y/N] "
    )
