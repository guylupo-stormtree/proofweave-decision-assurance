"""Append-only, hash-chained JSON Lines ledger with a content-addressed blob store (t1 → t2).

ledger.jsonl: one line per evidence record:
  {...record, "seq": n, "prev_hash": h(n-1), "record_hash": h(n)}
  h(n) = sha256(canonical record including seq and prev_hash). First prev_hash = "genesis".
blobs/<sha256>: native files referenced by records' source_ref (stored once, never altered).

One bundle = one append batch; the acknowledgement (t2) is returned after the batch is written
and, under the declared durability "fsync-per-bundle", flushed to disk. Updates and deletes are
not offered; `verify()` detects any alteration, deletion or reordering of accepted records.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterator

from ..hashing import sha256_bytes, sha256_json

GENESIS = "genesis"


class LedgerError(Exception):
    pass


class Ledger:
    def __init__(self, path: Path, durability: str = "fsync-per-bundle"):
        self.dir = Path(path)
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "blobs").mkdir(exist_ok=True)
        self.file = self.dir / "ledger.jsonl"
        if durability not in ("fsync-per-bundle", "none"):
            raise LedgerError(f"unknown durability {durability}")
        self.durability = durability
        self._seq, self._head = -1, GENESIS
        for r in self.records():
            self._seq, self._head = r["seq"], r["record_hash"]

    @property
    def head(self) -> tuple[int, str]:
        return self._seq, self._head

    def put_blob(self, data: bytes) -> str:
        h = sha256_bytes(data)
        p = self.dir / "blobs" / h
        if not p.exists():
            tmp = p.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(p)
        return h

    def blob(self, sha: str) -> bytes:
        return (self.dir / "blobs" / sha).read_bytes()

    def append_batch(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out, lines = [], []
        seq, prev = self._seq, self._head
        for rec in records:
            if {"seq", "prev_hash", "record_hash"} & rec.keys():
                raise LedgerError("records may not carry ledger fields")
            seq += 1
            r = {**rec, "seq": seq, "prev_hash": prev}
            r["record_hash"] = sha256_json(r)
            prev = r["record_hash"]
            out.append(r)
            lines.append(json.dumps(r, sort_keys=True, ensure_ascii=False))
        with self.file.open("a", encoding="utf-8") as f:
            if lines:
                f.write("\n".join(lines) + "\n")
            f.flush()
            if self.durability == "fsync-per-bundle":
                os.fsync(f.fileno())
        self._seq, self._head = seq, prev
        return out

    def records(self, after_seq: int = -1) -> Iterator[dict[str, Any]]:
        if not self.file.exists():
            return
        with self.file.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    if r["seq"] > after_seq:
                        yield r

    def verify(self) -> list[str]:
        problems, prev, expect = [], GENESIS, 0
        for r in self.records():
            body = {k: v for k, v in r.items() if k != "record_hash"}
            if r["seq"] != expect:
                problems.append(f"seq {r['seq']} expected {expect}")
            if r["prev_hash"] != prev:
                problems.append(f"seq {r['seq']}: prev_hash mismatch")
            if sha256_json(body) != r["record_hash"]:
                problems.append(f"seq {r['seq']}: record altered")
            ref = r.get("source_ref", {})
            if ref.get("sha256") and not (self.dir / "blobs" / ref["sha256"]).exists():
                problems.append(f"seq {r['seq']}: native blob {ref['sha256'][:12]} missing")
            prev, expect = r["record_hash"], expect + 1
        return problems
