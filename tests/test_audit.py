import json
import threading

from anvil import audit
from anvil.audit import AuditLog


def write_three(path):
    log = AuditLog(path, clock=lambda: 1700000000.0)
    log.append("gateway.started", server="demo")
    log.append("call.allowed", tool="read_file", arguments={"path": "a.txt"})
    log.append("call.denied", tool="shell_exec", reason="No shell.")
    return log


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def test_a_fresh_log_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_three(path)
    result = audit.verify(path)
    assert result.ok and result.records == 3


def test_records_are_numbered_and_chained(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_three(path)
    records = [json.loads(line) for line in lines(path)]
    assert [r["seq"] for r in records] == [1, 2, 3]
    assert records[0]["prev"] == audit.GENESIS
    assert records[1]["prev"] == records[0]["hash"]
    assert records[2]["prev"] == records[1]["hash"]
    assert records[1]["tool"] == "read_file" and records[1]["ts"] == 1700000000.0


def test_editing_a_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_three(path)
    rows = lines(path)
    rows[1] = rows[1].replace("read_file", "list_files")
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    result = audit.verify(path)
    assert not result.ok
    assert result.line == 2 and result.records == 1
    assert "modified" in result.problem


def test_deleting_a_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_three(path)
    rows = lines(path)
    del rows[1]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    result = audit.verify(path)
    assert not result.ok and result.line == 2


def test_reordering_records_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_three(path)
    rows = lines(path)
    rows[1], rows[2] = rows[2], rows[1]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    assert not audit.verify(path).ok


def test_a_forged_record_appended_by_hand_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_three(path)
    forged = {"seq": 4, "ts": 1.0, "event": "call.allowed", "tool": "shell_exec", "prev": "f" * 64, "hash": "e" * 64}
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(forged) + "\n")
    result = audit.verify(path)
    assert not result.ok and result.line == 4 and result.records == 3


def test_a_line_that_is_not_a_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_three(path)
    with path.open("a", encoding="utf-8") as stream:
        stream.write("oops\n")
    result = audit.verify(path)
    assert not result.ok and result.line == 4 and "not valid JSON" in result.problem


def test_reopening_a_log_continues_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_three(path)
    AuditLog(path).append("call.allowed", tool="read_file")
    records = [json.loads(line) for line in lines(path)]
    assert [r["seq"] for r in records] == [1, 2, 3, 4]
    assert records[3]["prev"] == records[2]["hash"]
    assert audit.verify(path).ok


def test_an_empty_log_verifies_with_zero_records(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    result = audit.verify(path)
    assert result.ok and result.records == 0


def test_a_log_without_a_path_keeps_records_in_memory():
    log = AuditLog()
    log.append("call.allowed", tool="x")
    log.append("call.denied", tool="y")
    assert [r["event"] for r in log.records] == ["call.allowed", "call.denied"]
    assert log.records[1]["prev"] == log.records[0]["hash"]


def test_concurrent_appends_keep_the_chain_intact(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)

    def worker(n):
        for i in range(50):
            log.append("call.allowed", tool=f"t{n}", i=i)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    result = audit.verify(path)
    assert result.ok and result.records == 400
