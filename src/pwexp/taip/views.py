"""Divergent-pair selection (paper Eqs. jaccard, divergent-pairs) and the registered evidence views P0–P9, P2w.

Pathway signature of a run = its analysis units (function, source, line) and validated chains (ordered
value ids), read from the sealed corpus graph. Comparable = same model alias (fixed model/context) and a
non-empty signature. The illustrative pair is the lexicographically first comparable GREEN pair with
J < τ in immutable run order; selection never maximises an assurance gap. Without such a pair, single-run
views use the first GREEN run R+ and P4/P5 are unattained.
"""
from __future__ import annotations

from itertools import combinations
from typing import Any

from ..proofweave.graph import InMemoryGraphStore
from .evaluate import View


def signatures(store: InMemoryGraphStore) -> dict[str, frozenset]:
    sig: dict[str, set] = {}
    for n in store.nodes().values():
        if n["kind"] != "run" or n["attrs"]["run"].startswith("semgrep/"):
            continue
        s = sig.setdefault(n["attrs"]["run"], set())
        for e in store.out_edges(n["id"], "observed"):
            u = store.nodes()[e["dst"]]["attrs"]
            s.add(("A", u.get("function"), u.get("source"), u.get("line")))
        for e in store.out_edges(n["id"], "validated"):
            steps = sorted(store.out_edges(e["dst"], "step"), key=lambda x: x["attrs"]["i"])
            s.add(("V",) + tuple(x["dst"] for x in steps))
    return {k: frozenset(v) for k, v in sig.items()}


def jaccard(a: frozenset, b: frozenset) -> float | None:
    u = a | b
    return None if not u else len(a & b) / len(u)


def select_pair(store: InMemoryGraphStore, verdicts: dict[str, bool], tau: float) -> dict[str, Any]:
    sig = signatures(store)
    green = sorted(r for r in sig if verdicts.get(r) and sig[r])
    table, qualifying = [], []
    for a, b in combinations(green, 2):
        comparable = a.split("/")[0] == b.split("/")[0]
        j = jaccard(sig[a], sig[b]) if comparable else None
        table.append({"pair": [a, b], "comparable": comparable, "jaccard": None if j is None else round(j, 4)})
        if comparable and j is not None and j < tau:
            qualifying.append((a, b))
    return {"tau": tau, "green_observable": green, "eligible_pairs": sum(t["comparable"] for t in table),
            "qualifying_pairs": len(qualifying), "selected": list(qualifying[0]) if qualifying else None,
            "r_plus": green[0] if green else None, "pairwise": table}


def build(selection: dict[str, Any], semgrep_runs: list[str], green_semgrep: list[str],
          all_green_runs: list[str]) -> list[View]:
    pair = selection["selected"]
    a = pair[0] if pair else selection["r_plus"]
    b = pair[1] if pair else None
    s = green_semgrep[0] if green_semgrep else None
    un = lambda vid, why: View(vid, [], attainable=False, note=why)  # noqa: E731
    v: list[View] = [View("P0", [], "no control evidence")]
    v.append(View("P1", [s], "Semgrep only") if s else un("P1", "no GREEN Semgrep run"))
    v.append(View("P2", [a], "RepoAudit run A only") if a else un("P2", "no GREEN RepoAudit run"))
    v.append(View("P2w", [a] if a else [], "run A with all witnesses to one supported requirement withheld"))
    v.append(View("P3", [a, s], "run A and Semgrep") if a and s else un("P3", "run A or Semgrep unavailable"))
    v.append(View("P4", [a, b], "runs A and B") if b else un("P4", "no qualifying divergent pair"))
    v.append(View("P5", [x for x in (a, b, s) if x], "natural Three-Greens candidate: A, B, Semgrep")
             if b and s else un("P5", "no qualifying divergent pair or no GREEN Semgrep run"))
    v.append(View("P6", [x for x in (a, b, s) if x], "P5 with all witnesses to one supported requirement withheld"))
    v.append(View("P7", sorted(all_green_runs + green_semgrep), "complete-evidence view: every GREEN run (declared rule)"))
    base = [x for x in (a, b, s) if x]
    v.append(View("P8", base, "run A declared incompatible with the decision context",
                  incompatible_runs=[a] if a else []))
    v.append(View("P9", base, "run A's witness records replaced by altered copies", mutated={}))
    return v
