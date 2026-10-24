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
"""
from __future__ import annotations

from typing import Any, Iterable

from .graph import InMemoryGraphStore


class QueryAPI:
    def __init__(self, store: InMemoryGraphStore):
        self.store = store

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
