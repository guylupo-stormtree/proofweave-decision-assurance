"""Decision adapter (DR-23): one decision bundle → intent, policy and decision observations.

Every observation points at the exact bytes it was read from: a JSON pointer into
decision_context.json or decision.json, or the whole policy file. Nothing is inferred beyond what
the files state. The binding itself is built by the evidence plane (ingress.ingest_decision), because
it names ledger records that exist only after the basis runs were ingested.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...hashing import sha256_file
from ..decision_bundle import load
from .repoaudit import Observation


def decision_run(decision_id: str) -> str:
    """The ledger `run` of a decision's own records (kept apart from its basis runs)."""
    return f"decision/{decision_id}"


def parse(bundle: Path) -> tuple[dict[str, Any], list[Observation]]:
    bundle = Path(bundle)
    b = load(bundle)
    ctx, dec = b["context"], b["decision"]
    pref = ctx["policy_ref"]
    ctx_sha, dec_sha = sha256_file(bundle / "decision_context.json"), sha256_file(bundle / "decision.json")
    policy = json.loads((bundle / pref["file"]).read_bytes())
    obs = [
        Observation("proofweave.intent", dict(ctx["intent"]),
                    {"file": "decision_context.json", "sha256": ctx_sha, "pointer": "/intent"},
                    ctx["context_written_at"]),
        Observation("proofweave.policy", {"id": pref["id"], "version": pref["version"], "sha256": pref["sha256"],
                                          "content": policy},
                    {"file": pref["file"], "sha256": pref["sha256"]}, ctx["context_written_at"]),
        Observation("proofweave.decision", {
            "decision_id": dec["decision_id"], "control_id": ctx["control_id"],
            "control_version": ctx["control_version"], "verdict": dec["verdict"], "per_run": dec["per_run"],
            "decision_rule": ctx["decision_rule"], "basis_runs": ctx["basis_runs"],
            "context_written_at": ctx["context_written_at"], "decided_at": dec["decided_at"],
            "harness_version": dec["harness_version"]},
            {"file": "decision.json", "sha256": dec_sha, "pointer": ""}, dec["decided_at"]),
    ]
    return b, obs
