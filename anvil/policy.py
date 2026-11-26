"""Policy: ordered rules that decide what happens to each tool call.

A policy is a TOML file. Rules are checked top to bottom and the first rule whose
``tool`` glob matches the tool name wins. If nothing matches, ``default`` applies.

    default = "deny"

    [[rule]]
    tool = "read_file"
    action = "allow"

      [[rule.arg]]
      name = "path"
      deny_pattern = '(^|/)\\.(ssh|aws)(/|$)'

    [[rule]]
    tool = "delete_*"
    action = "approve"

Argument constraints belong to ``allow`` and ``approve`` rules. They narrow the
grant: a call that matches the rule but breaks a constraint is denied.
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ACTIONS = ("allow", "deny", "approve")
NEW_TOOL_MODES = ("pin", "block")


class PolicyError(ValueError):
    """The policy file is malformed. The message says where."""


@dataclass(frozen=True)
class ArgRule:
    """A constraint on one argument of a tool call.

    ``name`` may be a dotted path into nested objects, such as ``options.path``.
    """

    name: str
    deny_pattern: re.Pattern[str] | None = None
    allow_pattern: re.Pattern[str] | None = None
    max_length: int | None = None
    required: bool = False

    def violation(self, arguments: dict[str, Any]) -> str | None:
        """Return why ``arguments`` break this constraint, or None if they do not."""
        found, value = _lookup(arguments, self.name)
        if not found:
            return f"argument '{self.name}' is required" if self.required else None
        text = value if isinstance(value, str) else _compact(value)
        if self.max_length is not None and len(text) > self.max_length:
            return f"argument '{self.name}' is longer than {self.max_length} characters"
        if self.deny_pattern is not None and self.deny_pattern.search(text):
            return f"argument '{self.name}' matches a denied pattern"
        if self.allow_pattern is not None and not self.allow_pattern.fullmatch(text):
            return f"argument '{self.name}' does not match the allowed pattern"
        return None


@dataclass(frozen=True)
class Rule:
    tool: str
    action: str
    reason: str = ""
    args: tuple[ArgRule, ...] = ()

    def matches(self, tool_name: str) -> bool:
        return fnmatch.fnmatchcase(tool_name, self.tool)


@dataclass(frozen=True)
class Verdict:
    """The decision for one call. ``rule`` is the glob that matched, or None for the default."""

    action: str
    reason: str
    rule: str | None = None


@dataclass
class Policy:
    default: str = "deny"
    rules: list[Rule] = field(default_factory=list)
    # Tools the policy can never allow are removed from tools/list.
    hide_denied: bool = True
    # Redaction.
    redact_results: bool = True
    redact_audit: bool = True
    # Prompt-injection scanning. Scores run from 0 to 100.
    injection_enabled: bool = True
    injection_flag_at: int = 25
    injection_block_at: int = 60
    # Tool pinning.
    pinning_enabled: bool = True
    on_new_tool: str = "pin"
    # Human approval.
    approval_timeout: float = 60.0
    # Elicitation requests that ask the person for a credential are refused.
    elicitation_block_credentials: bool = True

    def match(self, tool_name: str) -> Rule | None:
        for rule in self.rules:
            if rule.matches(tool_name):
                return rule
        return None

    def evaluate(self, tool_name: str, arguments: dict[str, Any] | None = None) -> Verdict:
        """Decide what happens to a call of ``tool_name`` with ``arguments``."""
        rule = self.match(tool_name)
        if rule is None:
            return Verdict(self.default, f"no rule matches '{tool_name}'; default is {self.default}")
        if rule.action == "deny":
            return Verdict("deny", rule.reason or f"rule '{rule.tool}' denies this tool", rule.tool)
        for constraint in rule.args:
            problem = constraint.violation(arguments or {})
            if problem:
                return Verdict("deny", problem, rule.tool)
        return Verdict(rule.action, rule.reason or f"rule '{rule.tool}'", rule.tool)

    def visible(self, tool_name: str) -> bool:
        """False when no arguments could ever get this tool past the policy."""
        rule = self.match(tool_name)
        action = rule.action if rule else self.default
        return action != "deny"


def load(path: str | Path) -> Policy:
    """Read a policy from a TOML file."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc.strerror or exc}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise PolicyError(f"{path} is not valid TOML: {exc}") from exc
    return parse(data)


def parse(data: dict[str, Any]) -> Policy:
    """Build a policy from already-decoded TOML."""
    _only_keys(data, {"default", "hide_denied", "rule", "redaction", "injection", "pinning", "approval", "elicitation"}, "policy")
    policy = Policy()
    policy.default = _action(data.get("default", "deny"), "default")
    policy.hide_denied = _bool(data.get("hide_denied", True), "hide_denied")

    redaction = _table(data, "redaction", {"results", "audit"})
    policy.redact_results = _bool(redaction.get("results", True), "redaction.results")
    policy.redact_audit = _bool(redaction.get("audit", True), "redaction.audit")

    injection = _table(data, "injection", {"enabled", "flag_at", "block_at"})
    policy.injection_enabled = _bool(injection.get("enabled", True), "injection.enabled")
    policy.injection_flag_at = _score(injection.get("flag_at", 25), "injection.flag_at")
    policy.injection_block_at = _score(injection.get("block_at", 60), "injection.block_at")
    if policy.injection_flag_at > policy.injection_block_at:
        raise PolicyError("injection.flag_at must not be higher than injection.block_at")

    pinning = _table(data, "pinning", {"enabled", "on_new_tool"})
    policy.pinning_enabled = _bool(pinning.get("enabled", True), "pinning.enabled")
    policy.on_new_tool = pinning.get("on_new_tool", "pin")
    if policy.on_new_tool not in NEW_TOOL_MODES:
        raise PolicyError(f"pinning.on_new_tool must be one of {', '.join(NEW_TOOL_MODES)}")

    approval = _table(data, "approval", {"timeout_seconds"})
    timeout = approval.get("timeout_seconds", 60)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise PolicyError("approval.timeout_seconds must be a positive number")
    policy.approval_timeout = float(timeout)

    elicitation = _table(data, "elicitation", {"block_credentials"})
    policy.elicitation_block_credentials = _bool(
        elicitation.get("block_credentials", True), "elicitation.block_credentials"
    )

    rules = data.get("rule", [])
    if not isinstance(rules, list):
        raise PolicyError("'rule' must be written as [[rule]] tables")
    policy.rules = [_rule(item, index) for index, item in enumerate(rules, start=1)]
    return policy


def _rule(item: Any, index: int) -> Rule:
    where = f"rule #{index}"
    if not isinstance(item, dict):
        raise PolicyError(f"{where} must be a table")
    _only_keys(item, {"tool", "action", "reason", "arg"}, where)
    tool = item.get("tool")
    if not isinstance(tool, str) or not tool:
        raise PolicyError(f"{where} needs a 'tool' name or glob")
    action = _action(item.get("action"), f"{where} action")
    reason = item.get("reason", "")
    if not isinstance(reason, str):
        raise PolicyError(f"{where} reason must be a string")
    arg_items = item.get("arg", [])
    if not isinstance(arg_items, list):
        raise PolicyError(f"{where}: 'arg' must be written as [[rule.arg]] tables")
    if arg_items and action == "deny":
        raise PolicyError(f"{where}: argument constraints only apply to allow and approve rules")
    args = tuple(_arg(arg, f"{where} arg #{n}") for n, arg in enumerate(arg_items, start=1))
    return Rule(tool=tool, action=action, reason=reason, args=args)


def _arg(item: Any, where: str) -> ArgRule:
    if not isinstance(item, dict):
        raise PolicyError(f"{where} must be a table")
    _only_keys(item, {"name", "deny_pattern", "allow_pattern", "max_length", "required"}, where)
    name = item.get("name")
    if not isinstance(name, str) or not name:
        raise PolicyError(f"{where} needs a 'name'")
    max_length = item.get("max_length")
    if max_length is not None and (isinstance(max_length, bool) or not isinstance(max_length, int) or max_length < 0):
        raise PolicyError(f"{where} max_length must be a whole number, zero or more")
    return ArgRule(
        name=name,
        deny_pattern=_pattern(item.get("deny_pattern"), f"{where} deny_pattern"),
        allow_pattern=_pattern(item.get("allow_pattern"), f"{where} allow_pattern"),
        max_length=max_length,
        required=_bool(item.get("required", False), f"{where} required"),
    )


def _pattern(value: Any, where: str) -> re.Pattern[str] | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PolicyError(f"{where} must be a string")
    try:
        return re.compile(value)
    except re.error as exc:
        raise PolicyError(f"{where} is not a valid regular expression: {exc}") from exc


def _action(value: Any, where: str) -> str:
    if value not in ACTIONS:
        raise PolicyError(f"{where} must be one of {', '.join(ACTIONS)}")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where} must be true or false")
    return value


def _score(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise PolicyError(f"{where} must be a whole number from 0 to 100")
    return value


def _table(data: dict[str, Any], key: str, allowed: set[str]) -> dict[str, Any]:
    table = data.get(key, {})
    if not isinstance(table, dict):
        raise PolicyError(f"[{key}] must be a table")
    _only_keys(table, allowed, f"[{key}]")
    return table


def _only_keys(table: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise PolicyError(f"{where} has unknown key(s): {', '.join(unknown)}")


def _lookup(arguments: Any, dotted: str) -> tuple[bool, Any]:
    current = arguments
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _compact(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
