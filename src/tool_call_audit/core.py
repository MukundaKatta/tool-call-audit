"""Tamper-evident audit log for agent tool calls using SHA-256 chain.

Each :class:`AuditEntry` includes a ``entry_hash`` — the SHA-256 of its own
content plus the hash of the previous entry.  :meth:`AuditLog.verify` walks
the chain and raises :class:`TamperError` if any hash is inconsistent.

Example::

    from tool_call_audit import AuditLog

    log = AuditLog()
    log.record("search", {"q": "weather"}, result={"temp": 72})
    log.record("write_file", {"path": "/tmp/out.txt"}, result=True)

    log.verify()  # passes — chain is intact

    # Serialise / reload
    jsonl = log.to_jsonl()
    log2 = AuditLog.from_jsonl(jsonl)
    log2.verify()  # still passes
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

# Sentinel hash for the genesis entry (no predecessor)
_GENESIS_HASH = "0" * 64


class TamperError(ValueError):
    """Raised when the hash chain fails verification."""


def _canonical(obj: Any) -> str:
    """Deterministic, sorted JSON serialisation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _compute_hash(
    entry_id: int,
    tool_name: str,
    args: dict[str, Any],
    result: Any,
    timestamp: float,
    prev_hash: str,
) -> str:
    """Compute the SHA-256 entry hash from its fields and the predecessor hash."""
    payload = _canonical(
        {
            "entry_id": entry_id,
            "tool_name": tool_name,
            "args": args,
            "result": result,
            "timestamp": timestamp,
            "prev_hash": prev_hash,
        }
    )
    return _sha256(payload)


@dataclass
class AuditEntry:
    """One entry in the audit chain.

    Attributes:
        entry_id:    Sequential integer (1-based).
        tool_name:   Name of the tool that was called.
        args:        Arguments passed to the tool.
        result:      Return value of the tool (serialisable).
        timestamp:   Unix timestamp when the call was recorded.
        prev_hash:   Hash of the preceding entry (``0*64`` for the first).
        entry_hash:  SHA-256 of this entry's canonical fields + *prev_hash*.
    """

    entry_id: int
    tool_name: str
    args: dict[str, Any]
    result: Any
    timestamp: float
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict."""
        return {
            "entry_id": self.entry_id,
            "tool_name": self.tool_name,
            "args": self.args,
            "result": self.result,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuditEntry:
        """Reconstruct from a :meth:`to_dict` payload."""
        return cls(
            entry_id=d["entry_id"],
            tool_name=d["tool_name"],
            args=d.get("args", {}),
            result=d.get("result"),
            timestamp=d["timestamp"],
            prev_hash=d["prev_hash"],
            entry_hash=d["entry_hash"],
        )

    def is_hash_valid(self) -> bool:
        """Recompute the expected hash and compare to ``entry_hash``."""
        expected = _compute_hash(
            self.entry_id,
            self.tool_name,
            self.args,
            self.result,
            self.timestamp,
            self.prev_hash,
        )
        return self.entry_hash == expected

    def __repr__(self) -> str:
        return (
            f"AuditEntry(id={self.entry_id},"
            f" tool={self.tool_name!r},"
            f" hash={self.entry_hash[:8]}...)"
        )


@dataclass
class _LogState:
    """Internal mutable state kept separate from the public interface."""

    entries: list[AuditEntry] = field(default_factory=list)
    last_hash: str = _GENESIS_HASH


class AuditLog:
    """Tamper-evident log of tool calls.

    Args:
        clock: Optional callable returning current Unix time (seconds).
               Defaults to :func:`time.time`.
    """

    def __init__(self, *, clock: Any = None) -> None:
        self._clock = clock if clock is not None else time.time
        self._state = _LogState()

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def record(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        *,
        result: Any = None,
    ) -> AuditEntry:
        """Append a tool-call entry to the log.

        Args:
            tool_name: Name of the tool invoked.
            args:      Dict of arguments (defaults to empty dict).
            result:    Return value of the tool.

        Returns:
            The newly created :class:`AuditEntry`.
        """
        safe_args: dict[str, Any] = args if args is not None else {}
        ts = self._clock()
        entry_id = len(self._state.entries) + 1
        entry_hash = _compute_hash(
            entry_id, tool_name, safe_args, result, ts, self._state.last_hash
        )
        entry = AuditEntry(
            entry_id=entry_id,
            tool_name=tool_name,
            args=safe_args,
            result=result,
            timestamp=ts,
            prev_hash=self._state.last_hash,
            entry_hash=entry_hash,
        )
        self._state.entries.append(entry)
        self._state.last_hash = entry_hash
        return entry

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def entries(self) -> list[AuditEntry]:
        """Return all entries in recording order."""
        return list(self._state.entries)

    def get(self, entry_id: int) -> AuditEntry | None:
        """Return the entry with the given *entry_id*, or ``None``."""
        if 1 <= entry_id <= len(self._state.entries):
            return self._state.entries[entry_id - 1]
        return None

    def __len__(self) -> int:
        return len(self._state.entries)

    def is_empty(self) -> bool:
        """``True`` when no entries have been recorded."""
        return len(self._state.entries) == 0

    def head(self) -> str:
        """Return the current chain-tip hash.

        This is the ``entry_hash`` of the most recently recorded entry, or the
        genesis sentinel (``0`` * 64) for an empty log.

        A plain hash chain cannot, on its own, detect tampering with its final
        entry: an attacker who edits the last entry can simply recompute its
        ``entry_hash`` and :meth:`verify` will still pass, because no successor
        pins it via ``prev_hash``.  To close that gap, persist the value
        returned here out-of-band and pass it to :meth:`verify` (or
        :meth:`is_valid`) as ``expected_head`` on reload.
        """
        return self._state.last_hash

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, *, expected_head: str | None = None) -> None:
        """Walk the hash chain and raise :class:`TamperError` if any entry is invalid.

        Args:
            expected_head: Optional chain-tip hash captured earlier via
                :meth:`head`.  When given, the recomputed tip must match it;
                this is what detects tampering with the *final* entry, which a
                bare chain walk cannot catch on its own.

        Raises:
            :class:`TamperError`: on the first inconsistency found.
        """
        prev_hash = _GENESIS_HASH
        for entry in self._state.entries:
            if entry.prev_hash != prev_hash:
                raise TamperError(
                    f"Entry {entry.entry_id}: prev_hash mismatch"
                    f" (expected {prev_hash!r}, got {entry.prev_hash!r})"
                )
            if not entry.is_hash_valid():
                raise TamperError(
                    f"Entry {entry.entry_id}: entry_hash is invalid"
                    f" (data may have been tampered with)"
                )
            prev_hash = entry.entry_hash

        if expected_head is not None and prev_hash != expected_head:
            raise TamperError(
                f"Chain head mismatch (expected {expected_head!r}, got {prev_hash!r});"
                f" the final entry may have been tampered with"
            )

    def is_valid(self, *, expected_head: str | None = None) -> bool:
        """Return ``True`` when :meth:`verify` passes, ``False`` otherwise."""
        try:
            self.verify(expected_head=expected_head)
            return True
        except TamperError:
            return False

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_jsonl(self) -> str:
        """Serialise the log as a JSONL string."""
        return "\n".join(json.dumps(e.to_dict()) for e in self._state.entries)

    @classmethod
    def from_jsonl(cls, text: str, *, clock: Any = None) -> AuditLog:
        """Reconstruct an :class:`AuditLog` from a JSONL string.

        The loaded log is *not* automatically re-verified; call
        :meth:`verify` if you need to assert integrity.
        """
        log = cls(clock=clock)
        entries: list[AuditEntry] = []
        last_hash = _GENESIS_HASH
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            entry = AuditEntry.from_dict(d)
            entries.append(entry)
            last_hash = entry.entry_hash
        log._state = _LogState(entries=entries, last_hash=last_hash)
        return log

    def to_list(self) -> list[dict[str, Any]]:
        """Return all entries as a list of dicts."""
        return [e.to_dict() for e in self._state.entries]

    def __repr__(self) -> str:
        n = len(self._state.entries)
        return f"AuditLog(entries={n})"
