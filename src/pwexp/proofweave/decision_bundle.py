"""Decision bundles (DR-23, opt-in): a control decision recorded with its intent and policy-at-event.

A decision bundle is a directory next to the run bundles it refers to (Stage 1: `decisions/<decision_id>/`):

  decision_context.json        written BEFORE the first basis run starts: decision_id, control_id,
                               control_version, intent, policy_ref {id, version, file, sha256}, basis_runs
                               (planned run tags), decision_rule, context_written_at
  policy/<id>@<version>.json   the exact policy bytes declared in the protocol, copied with the context
  decision.json                written AFTER every basis run finished: decision_id, verdict (green|not_green),
                               per_run (run tag -> GREEN), decided_at, harness_version
  manifest.json                {kind: "decision", decision_id, files: {name: sha256}}

If no decision bundle exists, nothing in ProofWeave changes (the run-only corpus is byte-identical).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..hashing import canonical_json, sha256_bytes, sha256_file

RULES = ("DR-11", "all-green")
INTENT_FIELDS = ("intent_id", "action", "repo", "commit", "bug_type", "scope_ref", "requested_by", "created_at")


class DecisionBundleError(ValueError):
    pass


def now_us() -> str:
    """UTC time with microseconds, so the order of context, runs and decision is checkable."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _write_json(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def policy_file_name(policy_id: str, version: int | str) -> str:
    return f"policy/{policy_id}@{version}.json"


def write_context(bundle: Path, decision_id: str, control_id: str, control_version: str, intent: dict[str, Any],
                  policy_id: str, policy_version: int | str, policy_bytes: bytes, basis_runs: list[str],
                  decision_rule: str) -> dict[str, Any]:
    """Seal the decision context before the control runs. The policy is stored as canonical JSON."""
    bundle = Path(bundle)
    if bundle.exists():
        raise DecisionBundleError(f"{bundle} already exists")
    if decision_rule not in RULES:
        raise DecisionBundleError(f"unknown decision rule {decision_rule!r} (known: {', '.join(RULES)})")
    missing = [f for f in INTENT_FIELDS if f not in intent]
    if missing:
        raise DecisionBundleError(f"intent lacks {', '.join(missing)}")
    if not basis_runs:
        raise DecisionBundleError("a decision needs at least one basis run")
    try:
        policy_doc = json.loads(policy_bytes)
    except ValueError as e:
        raise DecisionBundleError(f"policy is not JSON: {e}") from e
    canon = canonical_json(policy_doc)
    canon = canon if isinstance(canon, bytes) else canon.encode()
    rel = policy_file_name(policy_id, policy_version)
    (bundle / "policy").mkdir(parents=True)
    (bundle / rel).write_bytes(canon)
    ctx = {"decision_id": decision_id, "control_id": control_id, "control_version": control_version,
           "intent": intent, "policy_ref": {"id": policy_id, "version": policy_version, "file": rel,
                                            "sha256": sha256_bytes(canon)},
           "basis_runs": list(basis_runs), "decision_rule": decision_rule, "context_written_at": now_us()}
    _write_json(bundle / "decision_context.json", ctx)
    return ctx


def decide(rule: str, per_run: dict[str, bool]) -> str:
    """Single-run decisions use the run's GREEN (DR-11); composite decisions are green iff all runs are."""
    if rule == "DR-11" and len(per_run) != 1:
        raise DecisionBundleError("rule DR-11 decides on exactly one basis run")
    return "green" if per_run and all(per_run.values()) else "not_green"


def write_decision(bundle: Path, per_run: dict[str, bool], harness_version: str) -> dict[str, Any]:
    """Record the decision after every basis run finished, and seal the bundle manifest."""
    bundle = Path(bundle)
    ctx = json.loads((bundle / "decision_context.json").read_text())
    if sorted(per_run) != sorted(ctx["basis_runs"]):
        raise DecisionBundleError(f"{ctx['decision_id']}: verdicts {sorted(per_run)} do not match the planned "
                                  f"basis {sorted(ctx['basis_runs'])}")
    dec = {"decision_id": ctx["decision_id"], "verdict": decide(ctx["decision_rule"], per_run),
           "per_run": dict(sorted(per_run.items())), "decided_at": now_us(), "harness_version": harness_version}
    _write_json(bundle / "decision.json", dec)
    files = {p.relative_to(bundle).as_posix(): sha256_file(p) for p in sorted(bundle.rglob("*"))
             if p.is_file() and p.name != "manifest.json"}
    _write_json(bundle / "manifest.json", {"kind": "decision", "decision_id": ctx["decision_id"], "files": files})
    return dec


def load(bundle: Path) -> dict[str, Any]:
    """Read and verify a decision bundle. Raises if a file is missing or does not match the manifest."""
    bundle = Path(bundle)
    try:
        man = json.loads((bundle / "manifest.json").read_text())
        ctx = json.loads((bundle / "decision_context.json").read_text())
        dec = json.loads((bundle / "decision.json").read_text())
    except (OSError, ValueError) as e:
        raise DecisionBundleError(f"{bundle}: incomplete decision bundle ({e})") from e
    ids = {man.get("decision_id"), ctx.get("decision_id"), dec.get("decision_id")}
    if man.get("kind") != "decision" or len(ids) != 1 or None in ids:
        raise DecisionBundleError(f"{bundle}: manifest, context and decision disagree on the decision id")
    for name, h in man.get("files", {}).items():
        if not (bundle / name).is_file() or sha256_file(bundle / name) != h:
            raise DecisionBundleError(f"{bundle}/{name}: missing or does not match the bundle manifest")
    pref = ctx["policy_ref"]
    if pref["file"] not in man["files"] or man["files"][pref["file"]] != pref["sha256"]:
        raise DecisionBundleError(f"{bundle}: policy file does not match its reference")
    return {"manifest": man, "context": ctx, "decision": dec}


def bundles(stage1_attempt: Path) -> list[Path]:
    d = Path(stage1_attempt) / "decisions"
    return sorted(p for p in d.iterdir() if p.is_dir()) if d.is_dir() else []
