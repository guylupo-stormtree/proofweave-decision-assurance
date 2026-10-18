"""Protocol declarations and the protocol lock (setup precondition).

protocol/protocol.yaml holds every declaration the manuscript's registration table requires.
`lock()` refuses while any required value is unset ("TODO"/null/empty), hashes the YAML and
every file it references (target snapshot manifest, required set R, its review record), and
writes protocol/protocol.lock.json. A campaign cycle can only start under a valid lock.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .hashing import canonical_json, sha256_file, sha256_json
from .paths import protocol_dir, repo_root

REQUIRED: dict[str, type | tuple] = {
    "protocol_version": int,
    "target.repository": str,
    "target.commit": str,
    "target.language": str,
    "target.bug_type": str,
    "target.snapshot_path": str,
    "required_set.path": str,
    "required_set.review_record": str,
    "green_mapping": str,
    "divergence.tau": (int, float),
    "divergence.signature": str,
    "acquisition.repoaudit_runs_per_model": int,
    "acquisition.semgrep_runs": int,
    "acquisition.temperature": (int, float),
    "acquisition.call_depth": int,
    "acquisition.timeout_s": int,
    "acquisition.models": list,
    "semgrep.version": str,
    "semgrep.ruleset": str,
    "timing.reference_threshold_s": (int, float),
    "timing.repetitions": int,
    "timing.volumes": list,
    "timing.durability": str,
    "selection_rule": str,
}
GREEN_MAPPINGS = {"DR-11": "complete (exit 0, no traceback, native log present, not timed out) "
                           "and zero accepted findings in native detect_info.json"}
FILE_FIELDS = ("required_set.path", "required_set.review_record")


class ProtocolError(Exception):
    pass


def _get(d: dict, dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _unset(v: Any) -> bool:
    return v is None or v == "" or v == [] or (isinstance(v, str) and v.strip().upper().startswith("TODO"))


def load(path: Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else protocol_dir() / "protocol.yaml"
    if not p.exists():
        raise ProtocolError(f"{p} not found")
    return yaml.safe_load(p.read_text()) or {}


def problems(proto: dict[str, Any], root: Path | None = None) -> list[str]:
    root = Path(root) if root else repo_root()
    out = []
    for key, typ in REQUIRED.items():
        v = _get(proto, key)
        if _unset(v):
            out.append(f"{key}: not set")
        elif not isinstance(v, typ) or isinstance(v, bool):
            out.append(f"{key}: expected {typ}, got {type(v).__name__}")
    tau = _get(proto, "divergence.tau")
    if isinstance(tau, (int, float)) and not 0 < tau < 1:
        out.append("divergence.tau: must satisfy 0 < tau < 1 (main.tex Eq. divergent-pairs)")
    if _get(proto, "green_mapping") not in (None, *GREEN_MAPPINGS) and not _unset(_get(proto, "green_mapping")):
        out.append(f"green_mapping: unknown mapping (known: {', '.join(GREEN_MAPPINGS)})")
    for m in _get(proto, "acquisition.models") or []:
        if not isinstance(m, dict) or m.get("provider") not in ("openai", "anthropic") or _unset(m.get("model")):
            out.append(f"acquisition.models: entry {m!r} needs provider openai|anthropic and a model name")
        if isinstance(m, dict) and "key" in m:
            out.append("acquisition.models: API keys must never appear in protocol.yaml (DR-20)")
    for key in FILE_FIELDS + ("target.snapshot_path",):
        v = _get(proto, key)
        if isinstance(v, str) and not _unset(v) and not (root / v).exists():
            out.append(f"{key}: {v} does not exist")
    return out


def lock(path: Path | None = None, root: Path | None = None) -> dict[str, Any]:
    root = Path(root) if root else repo_root()
    ppath = Path(path) if path else protocol_dir() / "protocol.yaml"
    proto = load(ppath)
    errs = problems(proto, root)
    if errs:
        raise ProtocolError("protocol not lockable:\n  " + "\n  ".join(errs))
    files = {"protocol.yaml": sha256_file(ppath)}
    for key in FILE_FIELDS:
        rel = _get(proto, key)
        files[rel] = sha256_file(root / rel)
    snap = root / _get(proto, "target.snapshot_path")
    from .hashing import tree_manifest, manifest_hash
    files["target_snapshot_manifest"] = manifest_hash(tree_manifest(snap)) if snap.is_dir() else sha256_file(snap)
    body = {"protocol": proto, "files": files}
    lock_doc = {"lock_sha256": sha256_json(body), **body,
                "locked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    out = ppath.parent / "protocol.lock.json"
    out.write_text(json.dumps(lock_doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return lock_doc


def check_lock(path: Path | None = None, root: Path | None = None) -> tuple[bool, str]:
    """True if protocol.lock.json exists and still matches protocol.yaml and referenced files."""
    root = Path(root) if root else repo_root()
    ppath = Path(path) if path else protocol_dir() / "protocol.yaml"
    lpath = ppath.parent / "protocol.lock.json"
    if not lpath.exists():
        return False, "no protocol.lock.json"
    doc = json.loads(lpath.read_text())
    body = {"protocol": doc["protocol"], "files": doc["files"]}
    if sha256_json(body) != doc.get("lock_sha256"):
        return False, "lock file altered"
    if sha256_file(ppath) != doc["files"].get("protocol.yaml"):
        return False, "protocol.yaml changed since lock (new protocol revision required)"
    for key in FILE_FIELDS:
        rel = _get(doc["protocol"], key)
        if not (root / rel).exists() or sha256_file(root / rel) != doc["files"].get(rel):
            return False, f"{rel} changed since lock"
    return True, doc["lock_sha256"]
