"""Query API: witness queries and the readiness probe (t3 → t4).

Witness queries answer "which retained evidence supports requirement r?" and return the ledger record
hashes behind each witness, so every answer is traceable to native bytes. Supported requirement kinds:

  {"kind": "A", "function": "<file>::<name>"}             an analysis unit about that function
  {"kind": "V", "functions": ["<file>::<a>", "<file>::<b>"]}
        a validated chain whose steps pass through those functions in that order
  {"kind": "S", "file": "<file>"}                          a Semgrep scan that covered that file
Unresolved functions never satisfy a requirement. Runs can be restricted (evidence views, Stage 4).
"""
from __future__ import annotations

from typing import Any, Iterable

from .graph import InMemoryGraphStore


class QueryAPI:
    def __init__(self, store: InMemoryGraphStore):
        self.store = store

    def _out(self, src: str, kind: str) -> list[dict[str, Any]]:
        return self.store.out_edges(src, kind)

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
                        out.append({"run": rid, "witness": e["dst"], "refs": sorted(refs)})
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
