"""Append-only, hash-chained JSON Lines log.

Each line is one record:  {"seq": n, "prev_hash": h(n-1), ...payload, "record_hash": h(n)}
where h(n) = sha256(canonical_json(record without "record_hash")). The first record's
prev_hash is "genesis". Any edit, deletion or reordering of an accepted line breaks
verification of every later line. Used for stage logs, publication records and
(separately, with its own durability policy) by the ProofWeave ledger.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterator

from .hashing import sha256_json

GENESIS = "genesis"


class ChainError(Exception):
    pass


class HashChainLog:
    def __init__(self, path: Path, fsync: bool = True):
        self.path = Path(path)
        self.fsync = fsync

    def records(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

    def head(self) -> tuple[int, str]:
        seq, h = -1, GENESIS
        for r in self.records():
            seq, h = r["seq"], r["record_hash"]
        return seq, h

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        if {"seq", "prev_hash", "record_hash"} & payload.keys():
            raise ChainError("payload may not set seq/prev_hash/record_hash")
        seq, prev = self.head()
        rec = {"seq": seq + 1, "prev_hash": prev, **payload}
        rec["record_hash"] = sha256_json(rec)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n"
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            if self.fsync:
                os.fsync(f.fileno())
        return rec

    def verify(self) -> list[str]:
        """Return a list of problems; empty means the chain is intact."""
        problems, prev, expect = [], GENESIS, 0
        for r in self.records():
            body = {k: v for k, v in r.items() if k != "record_hash"}
            if r.get("seq") != expect:
                problems.append(f"seq {r.get('seq')} expected {expect}")
            if r.get("prev_hash") != prev:
                problems.append(f"seq {r.get('seq')}: prev_hash mismatch")
            if sha256_json(body) != r.get("record_hash"):
                problems.append(f"seq {r.get('seq')}: record_hash mismatch (record altered)")
            prev, expect = r.get("record_hash"), expect + 1
        return problems
