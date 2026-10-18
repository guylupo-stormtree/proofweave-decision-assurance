"""TAIP: deterministic obligation evaluation, posture and gateway action (paper Eqs. admissible,
support-set, missing, obligation-state, posture). No language model takes part in any decision.

For a decision context d and an evidence view (which runs the gateway may see, plus controlled
conditions), each required item r is evaluated over admissible evidence only:
  admissible  Valid (record hash recomputes, native blob present) ∧ Compatible (run in the view, same
              commit, not synthetic, not declared incompatible) ∧ Current (fixed decision time)
  support     an admissible witness exists for r (via the Query API)
  violation   an admissible accepted finding involves r's function(s) or file
  state       FAIL if violation; PASS if supported; else INCONCLUSIVE
Posture: FAIL if any FAIL; PASS if all PASS; else INCONCLUSIVE; an empty/invalid set → INCONCLUSIVE.
Gateway: PASS → PROCEED; FAIL → HOLD; INCONCLUSIVE → HOLD.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..hashing import sha256_json
from ..proofweave.graph import InMemoryGraphStore
from ..proofweave.query import QueryAPI

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
PROCEED, HOLD = "PROCEED", "HOLD"


@dataclass
class View:
    """An evidence view (paper Table permutations). All fields are declarative and recorded."""
    id: str
    runs: list[str]
    purpose: str = ""
    withheld: list[str] = field(default_factory=list)          # requirement ids whose witnesses are withheld
    incompatible_runs: list[str] = field(default_factory=list)  # e.g. declared under a different commit
    mutated: dict[str, list[str]] = field(default_factory=dict)  # run -> requirement ids whose witness records are altered copies
    attainable: bool = True
    note: str = ""

    def manifest(self) -> dict[str, Any]:
        return {"id": self.id, "runs": sorted(self.runs), "purpose": self.purpose, "withheld": sorted(self.withheld),
                "incompatible_runs": sorted(self.incompatible_runs),
                "mutated": {k: sorted(v) for k, v in sorted(self.mutated.items())},
                "attainable": self.attainable, "note": self.note}


def _valid(rec: dict[str, Any]) -> bool:
    body = {k: v for k, v in rec.items() if k != "record_hash"}
    return sha256_json(body) == rec.get("record_hash")


class Evaluator:
    def __init__(self, store: InMemoryGraphStore, records: dict[str, dict[str, Any]], blobs: set[str],
                 commit: str = ""):
        self.store, self.query, self.records, self.blobs, self.commit = store, QueryAPI(store), records, blobs, commit

    # ------------------------------------------------------------------ admissibility
    def _admissible(self, ref: str, view: View, req_id: str, run: str) -> tuple[bool, str]:
        rec = self.records.get(ref)
        if rec is None:
            return False, "record not in ledger"
        if run in view.mutated and req_id in view.mutated[run]:
            rec = {**rec, "payload": {**rec["payload"], "mutated_copy": True}}  # isolated replay copy (P9)
        if not _valid(rec):
            return False, "integrity: record hash does not recompute"
        sha = (rec.get("source_ref") or {}).get("sha256")
        if sha and sha not in self.blobs:
            return False, "integrity: native source missing"
        if rec.get("synthetic"):
            return False, "synthetic record"
        if rec.get("run") in view.incompatible_runs or (self.commit and rec.get("commit") != self.commit):
            return False, "incompatible context"
        return True, ""

    def _witnesses(self, item: dict[str, Any], view: View) -> tuple[list[dict], list[dict]]:
        if item["id"] in view.withheld:
            return [], [{"reason": "withheld by view (controlled condition)"}]
        req = {"kind": item["kind"], **{k: item[k] for k in ("function", "functions", "file") if k in item}}
        ok, rejected = [], []
        for w in self.query.witnesses(req, runs=view.runs):
            bad = [r for ref in w["refs"] for r in [self._admissible(ref, view, item["id"], w["run"])] if not r[0]]
            (rejected if bad else ok).append({**w, **({"reason": bad[0][1]} if bad else {})})
        return ok, rejected

    def _violations(self, item: dict[str, Any], view: View) -> list[dict]:
        targets = set()
        if item["kind"] == "A":
            targets.add(f"fn:{item['function']}")
        elif item["kind"] == "V":
            targets.update(f"fn:{f}" for f in item["functions"])
        else:
            targets.add(f"file:{item['file']}")
        out = []
        for run in self.query.runs():
            rid = run["attrs"]["run"]
            if rid not in view.runs:
                continue
            for e in self.store.out_edges(run["id"], "reported"):
                hits = [x for x in self.store.out_edges(e["dst"]) if x["kind"] in ("involves", "in_file") and x["dst"] in targets]
                if hits and all(self._admissible(ref, view, item["id"], rid)[0] for ref in e["refs"]):
                    out.append({"run": rid, "finding": e["dst"], "refs": e["refs"]})
        return out

    # ------------------------------------------------------------------ decision
    def decide(self, required: dict[str, Any], view: View) -> dict[str, Any]:
        items = required.get("items") or []
        obligations = []
        for it in items:
            sup, rej = self._witnesses(it, view)
            vio = self._violations(it, view)
            state = FAIL if vio else (PASS if sup else INCONCLUSIVE)
            obligations.append({"id": it["id"], "kind": it["kind"], "state": state,
                                "witnesses": [{"run": w["run"], "witness": w["witness"], "refs": w["refs"]} for w in sup],
                                "rejected": [{"run": r.get("run"), "reason": r["reason"]} for r in rej],
                                "violations": vio})
        states = [o["state"] for o in obligations]
        posture = INCONCLUSIVE if not states else FAIL if FAIL in states else PASS if all(s == PASS for s in states) \
            else INCONCLUSIVE
        return {"view": view.manifest(), "posture": posture, "action": PROCEED if posture == PASS else HOLD,
                "supported": [o["id"] for o in obligations if o["state"] == PASS],
                "missing": [o["id"] for o in obligations if o["state"] == INCONCLUSIVE],
                "failed": [o["id"] for o in obligations if o["state"] == FAIL], "obligations": obligations}


def verdict_only(view: View, verdicts: dict[str, bool]) -> str:
    """Information-limited comparator (paper L752): PROCEED iff the view's runs all completed GREEN."""
    return PROCEED if view.runs and all(verdicts.get(r, False) for r in view.runs) else HOLD
