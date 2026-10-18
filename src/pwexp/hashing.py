"""Content hashing and canonical JSON (shared by every stage)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

_CHUNK = 1 << 20


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_json(obj: Any) -> str:
    return sha256_bytes(canonical_json(obj))


def tree_manifest(root: Path, exclude: Iterable[str] = ()) -> dict[str, str]:
    """{relative posix path: sha256} for every file under root, sorted by path."""
    root = Path(root)
    skip = set(exclude)
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            if rel in skip or any(part in skip for part in p.relative_to(root).parts):
                continue
            out[rel] = sha256_file(p)
    return out


def manifest_hash(manifest: dict[str, str]) -> str:
    return sha256_json(manifest)
