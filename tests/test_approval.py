import io
import threading

from anvil import approval
from anvil.approval import ApprovalRequest, CallbackApprover, DenyAll, TtyApprover

REQUEST = ApprovalRequest("delete_branch", {"name": "main"}, "rule 'delete_*'")


class Terminal:
    """Stands in for the controlling terminal: canned input, captured output."""

    def __init__(self, answer):
        self.reader = io.StringIO(answer)
        self.writer = io.StringIO()

    def open(self):
        return self.reader, self.writer


def test_deny_all_refuses():
    assert DenyAll().decide(REQUEST) is False


def test_callback_approver_returns_what_the_callback_says():
    assert CallbackApprover(lambda request: request.tool == "delete_branch").decide(REQUEST) is True
    assert CallbackApprover(lambda request: None).decide(REQUEST) is False


def test_yes_on_the_terminal_approves(monkeypatch):
    terminal = Terminal("y\n")
    monkeypatch.setattr(approval, "_open_terminal", terminal.open)
    assert TtyApprover(timeout=5).decide(REQUEST) is True
    shown = terminal.writer.getvalue()
    assert "delete_branch" in shown and '"name": "main"' in shown and "[y/N]" in shown


def test_anything_but_yes_denies(monkeypatch):
    for answer in ("n\n", "\n", "maybe\n", ""):
        monkeypatch.setattr(approval, "_open_terminal", Terminal(answer).open)
        assert TtyApprover(timeout=5).decide(REQUEST) is False


def test_no_terminal_means_denied(monkeypatch):
    def unavailable():
        raise OSError("no controlling terminal")

    monkeypatch.setattr(approval, "_open_terminal", unavailable)
    assert TtyApprover(timeout=5).decide(REQUEST) is False


def test_no_answer_in_time_means_denied(monkeypatch):
    release = threading.Event()

    class Silent(io.StringIO):
        def readline(self, *args):
            release.wait(10)
            return "y\n"

    writer = io.StringIO()
    monkeypatch.setattr(approval, "_open_terminal", lambda: (Silent(), writer))
    try:
        assert TtyApprover(timeout=0.2).decide(REQUEST) is False
        assert "no answer in time" in writer.getvalue()
    finally:
        release.set()


def test_long_arguments_are_truncated_in_the_prompt():
    shown = approval._render(ApprovalRequest("write_file", {"content": "x" * 5000}, "rule"))
    assert "(truncated)" in shown and len(shown) < 2600
