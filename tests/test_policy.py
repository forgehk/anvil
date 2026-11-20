from pathlib import Path

import pytest

from anvil import policy
from anvil.policy import PolicyError

BASE = {
    "default": "deny",
    "rule": [
        {
            "tool": "read_file",
            "action": "allow",
            "arg": [{"name": "path", "deny_pattern": r"(^|/)\.(ssh|aws)(/|$)", "max_length": 60}],
        },
        {"tool": "delete_*", "action": "approve"},
        {"tool": "shell_exec", "action": "deny", "reason": "No shell through this gateway."},
        {"tool": "db_*", "action": "allow"},
        {"tool": "db_drop", "action": "deny"},
    ],
}


def base():
    return policy.parse(BASE)


def test_default_applies_when_no_rule_matches():
    verdict = base().evaluate("send_email", {})
    assert verdict.action == "deny"
    assert verdict.rule is None
    assert "no rule matches" in verdict.reason


def test_first_matching_rule_wins():
    # db_* comes before db_drop, so the later deny is never reached.
    assert base().evaluate("db_drop", {}).action == "allow"


def test_matching_is_case_sensitive():
    assert base().evaluate("Read_File", {"path": "notes.txt"}).action == "deny"


def test_deny_rule_carries_its_reason():
    verdict = base().evaluate("shell_exec", {"cmd": "ls"})
    assert verdict.action == "deny"
    assert verdict.reason == "No shell through this gateway."
    assert verdict.rule == "shell_exec"


def test_glob_rule_can_ask_for_approval():
    verdict = base().evaluate("delete_branch", {"name": "old"})
    assert verdict.action == "approve"
    assert verdict.rule == "delete_*"


def test_allowed_when_constraints_hold():
    assert base().evaluate("read_file", {"path": "docs/readme.md"}).action == "allow"


@pytest.mark.parametrize("path", ["/home/me/.ssh/id_rsa", ".aws/credentials", "work/.ssh/config"])
def test_deny_pattern_turns_an_allow_into_a_deny(path):
    verdict = base().evaluate("read_file", {"path": path})
    assert verdict.action == "deny"
    assert "denied pattern" in verdict.reason


def test_max_length_is_enforced():
    verdict = base().evaluate("read_file", {"path": "a" * 61})
    assert verdict.action == "deny"
    assert "longer than 60" in verdict.reason


def test_allow_pattern_must_match_the_whole_value():
    rules = policy.parse(
        {"rule": [{"tool": "fetch", "action": "allow", "arg": [{"name": "url", "allow_pattern": r"https://api\.example\.com/.*"}]}]}
    )
    assert rules.evaluate("fetch", {"url": "https://api.example.com/v1/items"}).action == "allow"
    assert rules.evaluate("fetch", {"url": "https://api.example.com.evil.test/x"}).action == "deny"
    assert rules.evaluate("fetch", {"url": "see https://api.example.com/v1"}).action == "deny"


def test_constraint_can_reach_into_nested_arguments():
    rules = policy.parse(
        {"rule": [{"tool": "run_query", "action": "allow", "arg": [{"name": "options.sql", "deny_pattern": r"(?i)\bdrop\b"}]}]}
    )
    assert rules.evaluate("run_query", {"options": {"sql": "select 1"}}).action == "allow"
    assert rules.evaluate("run_query", {"options": {"sql": "DROP TABLE users"}}).action == "deny"


def test_required_argument_must_be_present():
    rules = policy.parse({"rule": [{"tool": "deploy", "action": "allow", "arg": [{"name": "env", "required": True}]}]})
    assert rules.evaluate("deploy", {"env": "staging"}).action == "allow"
    verdict = rules.evaluate("deploy", {})
    assert verdict.action == "deny"
    assert "required" in verdict.reason


def test_optional_argument_may_be_absent():
    assert base().evaluate("read_file", {}).action == "allow"


def test_non_string_arguments_are_checked_as_json():
    rules = policy.parse(
        {"rule": [{"tool": "write_rows", "action": "allow", "arg": [{"name": "rows", "deny_pattern": "admin", "max_length": 40}]}]}
    )
    assert rules.evaluate("write_rows", {"rows": [{"role": "viewer"}]}).action == "allow"
    assert rules.evaluate("write_rows", {"rows": [{"role": "admin"}]}).action == "deny"
    assert rules.evaluate("write_rows", {"rows": list(range(40))}).action == "deny"


def test_visible_is_false_only_for_tools_that_can_never_run():
    rules = base()
    assert rules.visible("read_file")
    assert rules.visible("delete_branch")
    assert not rules.visible("shell_exec")
    assert not rules.visible("send_email")


def test_default_can_be_allow():
    rules = policy.parse({"default": "allow", "rule": [{"tool": "shell_exec", "action": "deny"}]})
    assert rules.evaluate("anything", {}).action == "allow"
    assert rules.evaluate("shell_exec", {}).action == "deny"
    assert rules.visible("anything")


def test_settings_have_safe_defaults():
    rules = policy.parse({})
    assert rules.default == "deny"
    assert rules.redact_results and rules.redact_audit
    assert rules.injection_enabled and rules.pinning_enabled
    assert (rules.injection_flag_at, rules.injection_block_at) == (25, 60)
    assert rules.on_new_tool == "pin"


def test_load_reads_a_toml_file(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text(
        """
default = "deny"

[injection]
block_at = 80

[pinning]
on_new_tool = "block"

[approval]
timeout_seconds = 5

[[rule]]
tool = "read_file"
action = "allow"

  [[rule.arg]]
  name = "path"
  deny_pattern = '\\.env$'
""",
        encoding="utf-8",
    )
    rules = policy.load(path)
    assert rules.injection_block_at == 80
    assert rules.on_new_tool == "block"
    assert rules.approval_timeout == 5.0
    assert rules.evaluate("read_file", {"path": "app/.env"}).action == "deny"
    assert rules.evaluate("read_file", {"path": "app/main.py"}).action == "allow"


@pytest.mark.parametrize(
    "data, fragment",
    [
        ({"defualt": "deny"}, "unknown key"),
        ({"default": "maybe"}, "default must be one of"),
        ({"rule": [{"tool": "x", "action": "permit"}]}, "action must be one of"),
        ({"rule": [{"action": "allow"}]}, "needs a 'tool'"),
        ({"rule": [{"tool": "x", "action": "allow", "arg": [{"name": "p", "deny_pattern": "("}]}]}, "not a valid regular expression"),
        ({"rule": [{"tool": "x", "action": "deny", "arg": [{"name": "p"}]}]}, "only apply to allow and approve"),
        ({"rule": [{"tool": "x", "action": "allow", "arg": [{"deny_pattern": "a"}]}]}, "needs a 'name'"),
        ({"rule": [{"tool": "x", "action": "allow", "arg": [{"name": "p", "max_length": -1}]}]}, "max_length"),
        ({"rule": {"tool": "x", "action": "allow"}}, "[[rule]]"),
        ({"injection": {"flag_at": 70, "block_at": 60}}, "must not be higher"),
        ({"injection": {"block_at": 101}}, "from 0 to 100"),
        ({"pinning": {"on_new_tool": "ask"}}, "on_new_tool"),
        ({"approval": {"timeout_seconds": 0}}, "positive number"),
        ({"redaction": {"results": "yes"}}, "true or false"),
        ({"redaction": []}, "must be a table"),
    ],
)
def test_malformed_policies_are_rejected_with_a_pointer(data, fragment):
    with pytest.raises(PolicyError) as error:
        policy.parse(data)
    assert fragment in str(error.value)


def test_load_reports_a_missing_file(tmp_path):
    with pytest.raises(PolicyError, match="cannot read policy"):
        policy.load(tmp_path / "nope.toml")


def test_load_reports_invalid_toml(tmp_path):
    path = tmp_path / "broken.toml"
    path.write_text("default = ", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid TOML"):
        policy.load(path)


def test_the_example_policy_loads_and_behaves_as_its_comments_say():
    rules = policy.load(Path(__file__).resolve().parent.parent / "examples" / "policy.toml")
    assert rules.evaluate("read_text_file", {"path": "src/main.py"}).action == "allow"
    for secret_path in ("/home/me/.ssh/id_rsa", "app/.env", "app/.env.local", r"C:\Users\me\.aws\credentials"):
        assert rules.evaluate("read_text_file", {"path": secret_path}).action == "deny"
    assert rules.evaluate("read_text_file", {"path": "docs/environment.md"}).action == "allow"
    assert rules.evaluate("write_file", {"path": "a.txt"}).action == "approve"
    assert rules.evaluate("delete_file", {}).action == "deny"
    assert rules.evaluate("run_shell", {}).action == "deny"
