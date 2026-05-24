# tool-call-audit

Tamper-evident audit log for agent tool calls using a SHA-256 hash chain. Zero dependencies (uses Python stdlib `hashlib`).

## Install

```bash
pip install tool-call-audit
```

## Quick start

```python
from tool_call_audit import AuditLog

log = AuditLog()
log.record("search",     {"q": "weather"},        result={"temp": 72})
log.record("write_file", {"path": "/tmp/out.txt"}, result=True)

# Verify chain integrity
log.verify()  # raises TamperError if any entry was modified

# Serialise to JSONL
jsonl = log.to_jsonl()

# Reload and re-verify
log2 = AuditLog.from_jsonl(jsonl)
log2.verify()
```

## How it works

Each entry stores:
- `entry_hash` = SHA-256 of the entry's fields + `prev_hash`
- `prev_hash` = `entry_hash` of the previous entry (all-zeros for the first)

`verify()` recomputes every hash and confirms the chain is unbroken.  Mutating any field — args, result, timestamp, tool name — will break the chain and cause `verify()` to raise.

## API

### `AuditLog`

| Method | Description |
|---|---|
| `record(tool_name, args, *, result)` | Append an entry; returns `AuditEntry` |
| `entries()` | All entries in recording order |
| `get(entry_id)` | Look up an entry by ID (1-based), or `None` |
| `verify()` | Raise `TamperError` if any hash fails |
| `is_valid()` | Return `True` when `verify()` passes |
| `to_jsonl()` | Serialise to JSONL |
| `from_jsonl(text)` | Reconstruct from JSONL |
| `to_list()` | All entries as list of dicts |

### `AuditEntry`

| Attribute | Description |
|---|---|
| `entry_id` | Sequential ID (1-based) |
| `tool_name` | Tool that was called |
| `args` | Arguments dict |
| `result` | Return value |
| `timestamp` | Unix timestamp |
| `prev_hash` | Hash of the previous entry |
| `entry_hash` | SHA-256 of this entry's content |
| `is_hash_valid()` | Recompute and compare hash |

## License

MIT
