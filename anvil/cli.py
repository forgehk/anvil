"""Command line entry point.

    anvil run -p policy.toml -- <server command...>     proxy a server behind the policy
    anvil check policy.toml [--tool NAME --args JSON]   validate a policy, or dry-run one call
    anvil scan [FILE]                                   score text for injection and secrets
    anvil audit verify LOG                              check an audit log's hash chain
    anvil pins list|forget                              inspect or edit the lock file
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, audit, injection, policy as policy_module, redact
from .approval import DenyAll, TtyApprover
from .gateway import Gateway
from .pinning import PinStore
from .proxy import ProxyError, run as run_proxy

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        return args.handler(args)
    except (policy_module.PolicyError, ProxyError, ValueError, OSError) as exc:
        print(f"anvil: {exc}", file=sys.stderr)
        return EXIT_USAGE


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="anvil", description="Policy-enforcing gateway for MCP servers.")
    parser.add_argument("--version", action="version", version=f"anvil {__version__}")
    commands = parser.add_subparsers(metavar="command")

    run = commands.add_parser("run", help="proxy an MCP server behind a policy")
    run.add_argument("-p", "--policy", required=True, help="policy file (TOML)")
    run.add_argument("--audit", default="anvil-audit.jsonl", help="audit log path (default: %(default)s)")
    run.add_argument("--lock", default="anvil.lock", help="tool pin lock file (default: %(default)s)")
    run.add_argument(
        "--approve",
        choices=("tty", "deny"),
        default="tty",
        help="how 'approve' rules are answered: ask on the terminal, or refuse (default: %(default)s)",
    )
    run.add_argument("server", nargs=argparse.REMAINDER, help="the server command, after --")
    run.set_defaults(handler=_run)

    check = commands.add_parser("check", help="validate a policy, or dry-run one call against it")
    check.add_argument("policy", help="policy file (TOML)")
    check.add_argument("--tool", help="tool name to evaluate")
    check.add_argument("--args", default="{}", help="arguments for --tool, as a JSON object")
    check.set_defaults(handler=_check)

    scan = commands.add_parser("scan", help="score text for prompt injection and secrets")
    scan.add_argument("file", nargs="?", help="file to read (default: stdin)")
    scan.add_argument("--json", action="store_true", help="print the report as JSON")
    scan.add_argument("--fail-at", type=int, metavar="SCORE", help="exit 1 when the injection score reaches SCORE")
    scan.set_defaults(handler=_scan)

    audit_parser = commands.add_parser("audit", help="work with audit logs")
    audit_commands = audit_parser.add_subparsers(metavar="action")
    verify = audit_commands.add_parser("verify", help="check a log's hash chain")
    verify.add_argument("log")
    verify.set_defaults(handler=_audit_verify)

    pins = commands.add_parser("pins", help="inspect or edit pinned tools")
    pins.add_argument("--lock", default="anvil.lock", help="lock file (default: %(default)s)")
    pin_commands = pins.add_subparsers(metavar="action")
    pin_list = pin_commands.add_parser("list", help="show pinned tools")
    pin_list.set_defaults(handler=_pins_list)
    pin_forget = pin_commands.add_parser("forget", help="drop a pin so the tool's next definition is accepted")
    pin_forget.add_argument("name")
    pin_forget.set_defaults(handler=_pins_forget)
    return parser


def _run(args: argparse.Namespace) -> int:
    command = args.server[1:] if args.server[:1] == ["--"] else args.server
    if not command:
        print("anvil: give the server command after --, for example: anvil run -p policy.toml -- python server.py", file=sys.stderr)
        return EXIT_USAGE
    loaded = policy_module.load(args.policy)
    approver = TtyApprover(loaded.approval_timeout) if args.approve == "tty" else DenyAll()
    gateway = Gateway(loaded, approver=approver, audit=audit.AuditLog(args.audit), pins=PinStore(args.lock))
    gateway.audit.append("gateway.started", server=command[0], policy=str(args.policy))
    return run_proxy(gateway, command)


def _check(args: argparse.Namespace) -> int:
    loaded = policy_module.load(args.policy)
    if not args.tool:
        counts = {action: sum(1 for rule in loaded.rules if rule.action == action) for action in policy_module.ACTIONS}
        print(f"{args.policy}: ok")
        print(f"  default: {loaded.default}")
        print(f"  rules:   {len(loaded.rules)} ({counts['allow']} allow, {counts['approve']} approve, {counts['deny']} deny)")
        return EXIT_OK
    try:
        arguments = json.loads(args.args)
    except ValueError as exc:
        raise ValueError(f"--args is not valid JSON: {exc}") from exc
    if not isinstance(arguments, dict):
        raise ValueError("--args must be a JSON object")
    verdict = loaded.evaluate(args.tool, arguments)
    print(f"{verdict.action}: {verdict.reason}")
    return EXIT_OK


def _scan(args: argparse.Namespace) -> int:
    text = Path(args.file).read_text(encoding="utf-8", errors="replace") if args.file else sys.stdin.read()
    report = injection.scan(text)
    secrets = sorted({finding.kind for finding in redact.find(text)})
    if args.json:
        payload = {
            "score": report.score,
            "signals": [{"name": s.name, "weight": s.weight, "excerpt": s.excerpt} for s in report.signals],
            "secrets": secrets,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"injection score: {report.score}/100")
        for signal in report.signals:
            print(f"  +{signal.weight:<3} {signal.name}: {signal.excerpt}")
        print("secrets: " + (", ".join(secrets) if secrets else "none found"))
    if args.fail_at is not None and report.score >= args.fail_at:
        return EXIT_FAILED
    return EXIT_OK


def _audit_verify(args: argparse.Namespace) -> int:
    result = audit.verify(args.log)
    if result.ok:
        print(f"{args.log}: ok, {result.records} record(s), chain intact")
        return EXIT_OK
    print(f"{args.log}: BROKEN at line {result.line}: {result.problem} ({result.records} record(s) verified before it)")
    return EXIT_FAILED


def _pins_list(args: argparse.Namespace) -> int:
    store = PinStore(args.lock)
    if not store.names():
        print(f"{args.lock}: no pinned tools")
        return EXIT_OK
    for name in store.names():
        entry = store.entry(name) or {}
        print(f"{name}  {entry.get('sha256', '')[:16]}  pinned {entry.get('pinned_at', '?')}")
    return EXIT_OK


def _pins_forget(args: argparse.Namespace) -> int:
    store = PinStore(args.lock)
    if store.forget(args.name):
        print(f"forgot {args.name}; its next definition will be pinned as new")
        return EXIT_OK
    print(f"anvil: {args.name} is not pinned in {args.lock}", file=sys.stderr)
    return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
