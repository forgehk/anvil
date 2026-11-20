"""The stdio proxy: run an MCP server as a child process and stand in the middle.

MCP's stdio transport is one JSON-RPC message per line. The client writes to our
stdin and reads our stdout; we do the same with the child. Two threads pump the two
directions and hand each message to the gateway.

JSON-RPC batches (arrays) are split and handled one message at a time. MCP removed
batching in its 2025-06-18 revision, so this only matters for older clients.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any, BinaryIO, Sequence

from .gateway import Gateway

SHUTDOWN_GRACE_SECONDS = 5.0


class ProxyError(RuntimeError):
    pass


def run(
    gateway: Gateway,
    command: Sequence[str],
    *,
    client_in: BinaryIO | None = None,
    client_out: BinaryIO | None = None,
) -> int:
    """Proxy between the client streams and ``command``. Returns the server's exit code."""
    client_in = client_in or sys.stdin.buffer
    client_out = client_out or sys.stdout.buffer
    try:
        server = subprocess.Popen(list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError as exc:
        raise ProxyError(f"cannot start server {command[0]!r}: {exc.strerror or exc}") from exc
    assert server.stdin is not None and server.stdout is not None

    out_lock = threading.Lock()
    in_lock = threading.Lock()

    def to_client(message: Any) -> None:
        with out_lock:
            try:
                client_out.write(_encode(message))
                client_out.flush()
            except (OSError, ValueError):
                pass

    def to_server(message: Any) -> None:
        with in_lock:
            try:
                server.stdin.write(_encode(message))
                server.stdin.flush()
            except (OSError, ValueError):
                pass

    def pump_client() -> None:
        try:
            for raw in client_in:
                for message in _decode(raw, "client"):
                    outcome = gateway.from_client(message)
                    if outcome.forward is not None:
                        to_server(outcome.forward)
                    if outcome.reply is not None:
                        to_client(outcome.reply)
        finally:
            # The client is gone: let the server see end of input, then make sure it exits.
            with in_lock:
                try:
                    server.stdin.close()
                except OSError:
                    pass
            try:
                server.wait(timeout=SHUTDOWN_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                server.terminate()

    def pump_server() -> None:
        for raw in server.stdout:
            for message in _decode(raw, "server"):
                if isinstance(message, dict) and "method" in message:
                    outcome = gateway.from_server_request(message)
                    if outcome.forward is not None:
                        to_client(outcome.forward)
                    if outcome.reply is not None:
                        to_server(outcome.reply)
                    continue
                processed = gateway.from_server(message)
                if processed is not None:
                    to_client(processed)

    client_thread = threading.Thread(target=pump_client, name="anvil-client", daemon=True)
    server_thread = threading.Thread(target=pump_server, name="anvil-server", daemon=True)
    client_thread.start()
    server_thread.start()
    code = server.wait()
    server_thread.join(timeout=SHUTDOWN_GRACE_SECONDS)
    return code


def _encode(message: Any) -> bytes:
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _decode(raw: bytes, side: str) -> list[Any]:
    """Turn one line into zero or more messages. Lines that are not JSON are dropped."""
    line = raw.strip()
    if not line:
        return []
    try:
        message = json.loads(line)
    except (ValueError, UnicodeDecodeError):
        print(f"[anvil] dropped a line from the {side} that is not JSON", file=sys.stderr)
        return []
    return message if isinstance(message, list) else [message]
