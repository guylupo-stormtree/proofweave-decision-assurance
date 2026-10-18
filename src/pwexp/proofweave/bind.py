"""Bind: validate observations, apply privacy treatment, bind collection context (t0 → t1).

Produces evidence records shaped like the paper's envelope (Eq. envelope):
  id, producer, run, repo, commit, config (χ), collection_policy (π_col), event_type,
  source_ref, payload, payload_hash, time, completion
`ledger_ref` is added by the ledger on append.

Privacy treatment: absolute paths under the project root RepoAudit was given become
repository-relative; any other absolute path is reduced to "<external>/<basename>". Native
files are never altered: source_ref still points at their exact bytes in the blob store.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..hashing import sha256_json
from .adapters.repoaudit import Observation

EVENT_TYPES = {
    "harness.run_verdict": "harness",
    "repoaudit.analysis_unit": "repoaudit",
    "repoaudit.flow_fact": "repoaudit",
    "repoaudit.validation_request": "repoaudit",
    "repoaudit.validation_answer": "repoaudit",
    "repoaudit.finding": "repoaudit",
    "semgrep.scan": "semgrep",
    "semgrep.finding": "semgrep",
}


class BindError(ValueError):
    pass


@dataclass
class BindContext:
    run: str
    repo: str
    commit: str
    project_root: str | None
    config: dict[str, Any] = field(default_factory=dict)
    collection_policy: str | None = None
    completion: str | None = None
    synthetic: bool = False


def _rel(path: str, root: str | None) -> str:
    if root and path.startswith(root.rstrip("/") + "/"):
        return path[len(root.rstrip("/")) + 1:]
    if path.startswith("/"):
        return "<external>/" + path.rsplit("/", 1)[-1]
    return path


def _privacy(obj: Any, root: str | None) -> Any:
    if isinstance(obj, dict):
        return {k: (_rel(v, root) if k == "file" and isinstance(v, str) else _privacy(v, root)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_privacy(v, root) for v in obj]
    if isinstance(obj, str) and root and root in obj:
        return obj.replace(root.rstrip("/") + "/", "")
    return obj


def bind(observations: list[Observation], ctx: BindContext) -> list[dict[str, Any]]:
    records = []
    for o in observations:
        if o.event_type not in EVENT_TYPES:
            raise BindError(f"unknown event type {o.event_type}")
        if not o.source_ref or "sha256" not in o.source_ref:
            raise BindError(f"{o.event_type}: missing source reference")
        payload = _privacy(o.payload, ctx.project_root)
        rec = {
            "producer": EVENT_TYPES[o.event_type], "run": ctx.run, "repo": ctx.repo, "commit": ctx.commit,
            "config": ctx.config, "collection_policy": ctx.collection_policy, "event_type": o.event_type,
            "source_ref": o.source_ref, "payload": payload, "payload_hash": sha256_json(payload),
            "time": o.time, "completion": ctx.completion,
        }
        if ctx.synthetic:
            rec["synthetic"] = True
        rec["id"] = "ev-" + sha256_json({"run": ctx.run, "event_type": o.event_type, "source_ref": o.source_ref,
                                         "synthetic": ctx.synthetic})[:24]
        records.append(rec)
    return records
