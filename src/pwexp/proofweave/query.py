"""Query API: witness queries and the readiness probe (t3 → t4).

Witness queries answer "which retained evidence supports requirement r?" and return the ledger record
hashes behind each witness, so every answer is traceable to native bytes. Supported requirement kinds:

  {"kind": "A", "function": "<file>::<name>"}             an analysis unit about that function
  {"kind": "V", "functions": ["<file>::<a>", "<file>::<b>"]}
        the run carried a None along a → b (→ …): every consecutive step is a followed pathway step
        (RepoAudit analysed the next function with the value it received from the previous one), or a
        validated chain passes through those functions in that order. Each witness says which (`via`).
  {"kind": "S", "file": "<file>"}                          a Semgrep scan that covered that file
Unresolved functions never satisfy a requirement. Runs can be restricted (evidence views, Stage 4).

Decision queries (DR-23, need the ledger): `decision(id)`, `basis(id, kinds)` and `policy_text(record)`.
Each answer carries `status`: complete (binding found, every basis record resolves, and the recomputed
basis root matches), partial (something referenced is missing or does not match) or unavailable (no
binding for that decision). Partial and unavailable answers never establish absence.
"""
from __future__ import annotations

from typing import Any, Iterable

from ..hashing import sha256_json
from .graph import InMemoryGraphStore

COMPLETE, PARTIAL, UNAVAILABLE = "complete", "partial", "unavailable"


class QueryAPI:
    def __init__(self, store: InMemoryGraphStore, ledger: Any = None):
        self.store = store
        self.ledger = ledger
        self._index: tuple[Any, dict[str, dict[str, Any]], dict[str, dict[str, Any]]] | None = None

    # ------------------------------------------------------------------ decisions (DR-23)
    def _records(self) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        """(record id -> record, decision id -> binding record), rebuilt only when the ledger head moves."""
        if self.ledger is None:
            return {}, {}
        head = self.ledger.head
        if self._index is None or self._index[0] != head:
            by_id, bindings = {}, {}
            for r in self.ledger.records():
                by_id[r["id"]] = r
                if r["event_type"] == "proofweave.decision_binding":
                    bindings[r["payload"]["decision_id"]] = r
            self._index = (head, by_id, bindings)
        return self._index[1], self._index[2]

    def decisions(self) -> list[str]:
        return sorted(self._records()[1])

    def decision(self, decision_id: str) -> dict[str, Any]:
        by_id, bindings = self._records()
        b = bindings.get(decision_id)
        if b is None:
            return {"status": UNAVAILABLE, "binding": None, "intent": None, "policy": None, "decision": None}
        p = b["payload"]
        parts = {k: by_id.get(p[f"{k}_record"]) for k in ("intent", "policy", "decision")}
        basis = [by_id.get(i) for i in p["basis_record_ids"]]
        ok = all(parts.values()) and all(basis) and len(basis) == p["basis_count"] and \
            sha256_json(sorted(r["record_hash"] for r in basis)) == p["basis_root"] and \
            parts["policy"]["payload"].get("sha256") == p["policy_digest"]
        return {"status": COMPLETE if ok else PARTIAL, "binding": b, **parts}

    def basis(self, decision_id: str, kinds: Iterable[str] | None = None) -> dict[str, Any]:
        d = self.decision(decision_id)
        if d["status"] == UNAVAILABLE:
            return {"status": UNAVAILABLE, "records": []}
        by_id, _ = self._records()
        want = set(kinds) if kinds else None
        recs = [by_id[i] for i in d["binding"]["payload"]["basis_record_ids"] if i in by_id]
        return {"status": d["status"], "records": [r for r in recs if want is None or r["event_type"] in want]}

    def policy_text(self, policy_record: str) -> bytes | str:
        by_id, _ = self._records()
        r = by_id.get(policy_record)
        if r is None or r["event_type"] != "proofweave.policy":
            return UNAVAILABLE
        try:
            return self.ledger.blob(r["source_ref"]["sha256"])
        except OSError:
            return UNAVAILABLE

    def _out(self, src: str, kind: str) -> list[dict[str, Any]]:
        return self.store.out_edges(src, kind)

    def pathway(self, run: str) -> dict[tuple[str, str], dict[str, Any]]:
        """The run's followed steps {(from_fn, to_fn): {"via": "return"|"argument", "refs": [...]}}."""
        node = run if run.startswith("run:") else f"run:{run}"
        steps: dict[tuple[str, str], dict[str, Any]] = {}
        entered = {}
        for e in self._out(node, "observed"):
            u = self.store.nodes()[e["dst"]]
            about = [x for x in self._out(e["dst"], "about") if x["dst"].startswith("fn:")]
            if not about:
                continue
            to = about[0]["dst"]
            if u["attrs"].get("entry") == "return":
                for f in self._out(e["dst"], "entered_from"):
                    if f["dst"].startswith("fn:") and f["dst"] != to:
                        s = steps.setdefault((f["dst"], to), {"via": "return", "refs": set()})
                        s["refs"].update(e["refs"] + about[0]["refs"] + f["refs"])
            elif u["attrs"].get("entry") == "parameter":
                entered.setdefault(to, set()).update(e["refs"] + about[0]["refs"])
        for e in self._out(node, "passed"):
            cs = self.store.nodes()[e["dst"]]["attrs"]
            if cs["to"] in entered:
                s = steps.setdefault((cs["from"], cs["to"]), {"via": "argument", "refs": set()})
                s["refs"].update(e["refs"] + list(entered[cs["to"]]))
        return {k: {"via": v["via"], "refs": sorted(v["refs"])} for k, v in sorted(steps.items())}

    def runs(self) -> list[dict[str, Any]]:
        return sorted((n for n in self.store.nodes().values() if n["kind"] == "run"), key=lambda n: n["id"])

    def witnesses(self, req: dict[str, Any], runs: Iterable[str] | None = None) -> list[dict[str, Any]]:
        allowed = set(runs) if runs is not None else None
        out = []
        for run in self.runs():
            rid = run["attrs"]["run"]
            if allowed is not None and rid not in allowed:
                continue
            if req["kind"] == "A":
                target = f"fn:{req['function']}"
                for e in self._out(run["id"], "observed"):
                    about = [x for x in self._out(e["dst"], "about") if x["dst"] == target]
                    if about:
                        out.append({"run": rid, "witness": e["dst"], "refs": sorted(set(e["refs"] + about[0]["refs"]))})
            elif req["kind"] == "V":
                want = [f"fn:{f}" for f in req["functions"]]
                for e in self._out(run["id"], "validated"):
                    steps = sorted(self._out(e["dst"], "step"), key=lambda s: s["attrs"]["i"])
                    fns = []
                    for s in steps:
                        fns += [x["dst"] for x in self._out(s["dst"], "in")]
                    it = iter(fns)
                    if all(w in it for w in want):  # ordered subsequence
                        refs = set(e["refs"])
                        for s in steps:
                            refs.update(s["refs"])
                        out.append({"run": rid, "witness": e["dst"], "via": "validated", "refs": sorted(refs)})
                path = self.pathway(run["id"])
                pairs = list(zip(want, want[1:]))
                if pairs and all(p in path for p in pairs):
                    refs = sorted({r for p in pairs for r in path[p]["refs"]})
                    out.append({"run": rid, "witness": f"pathway:{rid}:{'>'.join(want)}", "via": "followed",
                                "refs": refs})
            elif req["kind"] == "S":
                for e in self._out(run["id"], "scanned"):
                    cov = [x for x in self._out(e["dst"], "covers") if x["dst"] == f"file:{req['file']}"]
                    if cov:
                        out.append({"run": rid, "witness": e["dst"], "refs": sorted(set(e["refs"] + cov[0]["refs"]))})
            else:
                raise ValueError(f"unknown requirement kind {req['kind']}")
        return out

    def probe(self, record_hashes: Iterable[str], watermark: int) -> bool:
        """Registered readiness probe: the bundle's records are materialised at a committed watermark."""
        return self.store.watermark >= watermark and self.store.has_refs(record_hashes)
