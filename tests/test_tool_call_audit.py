"""Tests for tool-call-audit."""

from __future__ import annotations

import json

import pytest

from tool_call_audit import AuditEntry, AuditLog, TamperError

# ---------------------------------------------------------------------------
# AuditEntry — basic
# ---------------------------------------------------------------------------


def test_entry_to_dict():
    entry = AuditEntry(
        entry_id=1,
        tool_name="search",
        args={"q": "test"},
        result={"hits": 3},
        timestamp=1000.0,
        prev_hash="0" * 64,
        entry_hash="abc",
    )
    d = entry.to_dict()
    assert d["entry_id"] == 1
    assert d["tool_name"] == "search"
    assert d["args"] == {"q": "test"}
    assert d["result"] == {"hits": 3}
    assert d["timestamp"] == 1000.0
    assert d["entry_hash"] == "abc"


def test_entry_from_dict_roundtrip():
    original = AuditEntry(
        entry_id=2,
        tool_name="write",
        args={"path": "/tmp/x"},
        result=True,
        timestamp=2000.0,
        prev_hash="aaa",
        entry_hash="bbb",
    )
    e2 = AuditEntry.from_dict(original.to_dict())
    assert e2.entry_id == 2
    assert e2.tool_name == "write"
    assert e2.result is True


def test_entry_repr():
    entry = AuditEntry(
        entry_id=1,
        tool_name="t",
        args={},
        result=None,
        timestamp=0.0,
        prev_hash="0" * 64,
        entry_hash="abc12345" + "x" * 56,
    )
    r = repr(entry)
    assert "1" in r
    assert "abc1234" in r


# ---------------------------------------------------------------------------
# AuditLog — construction
# ---------------------------------------------------------------------------


def test_new_log_empty():
    log = AuditLog()
    assert log.is_empty()
    assert len(log) == 0


def test_repr():
    log = AuditLog()
    assert "AuditLog" in repr(log)


# ---------------------------------------------------------------------------
# AuditLog — record
# ---------------------------------------------------------------------------


def test_record_returns_entry():
    log = AuditLog()
    e = log.record("search", {"q": "weather"})
    assert isinstance(e, AuditEntry)
    assert e.tool_name == "search"
    assert e.entry_id == 1


def test_record_increments_id():
    log = AuditLog()
    e1 = log.record("a", {})
    e2 = log.record("b", {})
    e3 = log.record("c", {})
    assert e1.entry_id == 1
    assert e2.entry_id == 2
    assert e3.entry_id == 3


def test_record_stores_result():
    log = AuditLog()
    e = log.record("t", {}, result={"key": "val"})
    assert e.result == {"key": "val"}


def test_record_default_args():
    log = AuditLog()
    e = log.record("ping")
    assert e.args == {}


def test_record_uses_clock():
    times = [100.0, 200.0]
    idx = 0

    def fake_clock():
        nonlocal idx
        v = times[min(idx, len(times) - 1)]
        idx += 1
        return v

    log = AuditLog(clock=fake_clock)
    e1 = log.record("a")
    e2 = log.record("b")
    assert e1.timestamp == 100.0
    assert e2.timestamp == 200.0


def test_record_chained_hashes():
    log = AuditLog()
    e1 = log.record("a", {})
    e2 = log.record("b", {})
    # e2's prev_hash should equal e1's entry_hash
    assert e2.prev_hash == e1.entry_hash


def test_first_entry_prev_hash_is_genesis():
    log = AuditLog()
    e = log.record("first", {})
    assert e.prev_hash == "0" * 64


def test_not_empty_after_record():
    log = AuditLog()
    log.record("x", {})
    assert not log.is_empty()
    assert len(log) == 1


# ---------------------------------------------------------------------------
# AuditLog — entries / get
# ---------------------------------------------------------------------------


def test_entries_returns_all():
    log = AuditLog()
    log.record("a")
    log.record("b")
    log.record("c")
    assert len(log.entries()) == 3


def test_entries_is_copy():
    log = AuditLog()
    log.record("a")
    entries = log.entries()
    entries.clear()
    assert len(log) == 1


def test_get_by_id():
    log = AuditLog()
    log.record("first")
    log.record("second")
    e = log.get(2)
    assert e is not None
    assert e.tool_name == "second"


def test_get_missing():
    log = AuditLog()
    assert log.get(99) is None


def test_get_zero_returns_none():
    log = AuditLog()
    log.record("x")
    assert log.get(0) is None


# ---------------------------------------------------------------------------
# AuditLog — verify / is_valid
# ---------------------------------------------------------------------------


def test_verify_empty_passes():
    log = AuditLog()
    log.verify()  # no exception


def test_verify_single_entry_passes():
    log = AuditLog()
    log.record("search", {"q": "test"}, result=42)
    log.verify()


def test_verify_chain_passes():
    log = AuditLog()
    for i in range(5):
        log.record(f"tool_{i}", {"i": i}, result=i * 2)
    log.verify()


def test_is_valid_true():
    log = AuditLog()
    log.record("a")
    assert log.is_valid()


def test_tamper_entry_hash_fails_verify():
    log = AuditLog()
    log.record("search", {"q": "weather"})
    # Corrupt the entry_hash
    log._state.entries[0].entry_hash = "deadbeef" + "0" * 56
    with pytest.raises(TamperError):
        log.verify()


def test_tamper_args_fails_verify():
    log = AuditLog()
    log.record("search", {"q": "weather"})
    # Mutate args after recording — hash no longer matches
    log._state.entries[0].args["q"] = "hacked"
    with pytest.raises(TamperError):
        log.verify()


def test_tamper_prev_hash_fails_verify():
    log = AuditLog()
    log.record("a")
    log.record("b")
    # Corrupt prev_hash of second entry
    log._state.entries[1].prev_hash = "0" * 64
    with pytest.raises(TamperError):
        log.verify()


def test_is_valid_false_on_tamper():
    log = AuditLog()
    log.record("x")
    log._state.entries[0].entry_hash = "bad"
    assert not log.is_valid()


# ---------------------------------------------------------------------------
# AuditLog — head / expected_head (tail-tamper detection)
# ---------------------------------------------------------------------------


def test_head_empty_is_genesis():
    log = AuditLog()
    assert log.head() == "0" * 64


def test_head_matches_last_entry_hash():
    log = AuditLog()
    log.record("a")
    e = log.record("b")
    assert log.head() == e.entry_hash


def test_verify_with_correct_expected_head_passes():
    log = AuditLog()
    log.record("a", {"x": 1})
    log.record("b", {"y": 2})
    log.verify(expected_head=log.head())  # no exception


def test_verify_with_wrong_expected_head_fails():
    log = AuditLog()
    log.record("a")
    with pytest.raises(TamperError):
        log.verify(expected_head="f" * 64)


def test_expected_head_detects_tail_tamper():
    """Recomputing the last entry's hash defeats a bare chain walk, but an
    anchored head catches it."""
    from tool_call_audit.core import _compute_hash

    log = AuditLog()
    log.record("a", {"x": 1})
    log.record("b", {"y": 2})
    anchored_head = log.head()

    # Attacker mutates the final entry AND recomputes a self-consistent hash.
    e = log._state.entries[-1]
    e.args["y"] = 999
    e.entry_hash = _compute_hash(
        e.entry_id, e.tool_name, e.args, e.result, e.timestamp, e.prev_hash
    )

    # A plain walk no longer catches it...
    assert log.is_valid()
    # ...but anchoring against the saved head does.
    assert not log.is_valid(expected_head=anchored_head)
    with pytest.raises(TamperError):
        log.verify(expected_head=anchored_head)


def test_head_survives_jsonl_roundtrip():
    log = AuditLog()
    log.record("a", {"x": 1})
    log.record("b", {"y": 2})
    head = log.head()
    log2 = AuditLog.from_jsonl(log.to_jsonl())
    assert log2.head() == head
    log2.verify(expected_head=head)


# ---------------------------------------------------------------------------
# AuditLog — is_hash_valid
# ---------------------------------------------------------------------------


def test_entry_is_hash_valid_true():
    log = AuditLog()
    e = log.record("t", {"k": "v"}, result=1)
    assert e.is_hash_valid()


def test_entry_is_hash_valid_false_after_mutation():
    log = AuditLog()
    e = log.record("t", {})
    e.args["injected"] = True
    assert not e.is_hash_valid()


# ---------------------------------------------------------------------------
# AuditLog — serialisation
# ---------------------------------------------------------------------------


def test_to_jsonl_each_line_valid_json():
    log = AuditLog()
    log.record("search", {"q": "x"})
    log.record("write", {"path": "/tmp/y"})
    lines = log.to_jsonl().splitlines()
    assert len(lines) == 2
    for line in lines:
        d = json.loads(line)
        assert "entry_hash" in d
        assert "prev_hash" in d


def test_from_jsonl_roundtrip():
    log = AuditLog()
    log.record("search", {"q": "test"}, result={"n": 5})
    log.record("write", {"path": "/x"}, result=True)

    jsonl = log.to_jsonl()
    log2 = AuditLog.from_jsonl(jsonl)

    assert len(log2) == 2
    assert log2.get(1).tool_name == "search"
    assert log2.get(2).result is True


def test_from_jsonl_verify_passes():
    log = AuditLog()
    for i in range(3):
        log.record(f"t{i}", {"i": i})
    log2 = AuditLog.from_jsonl(log.to_jsonl())
    log2.verify()


def test_from_jsonl_empty():
    log = AuditLog.from_jsonl("")
    assert log.is_empty()


def test_from_jsonl_skips_blank_lines():
    log = AuditLog()
    log.record("x")
    raw = "\n" + log.to_jsonl() + "\n\n"
    log2 = AuditLog.from_jsonl(raw)
    assert len(log2) == 1


def test_to_list():
    log = AuditLog()
    log.record("t", {"k": "v"})
    lst = log.to_list()
    assert isinstance(lst, list)
    assert lst[0]["tool_name"] == "t"
