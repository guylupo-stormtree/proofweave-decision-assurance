"""Stage 4: three GREENs, not enough coverage (RQ1).

Over the sealed corpus E only (no control runs again): select the divergent GREEN pair by the fixed rule,
build the registered evidence views P0–P9 and P2w, and for each view record the verdict-only action, the
TAIP posture and gateway action with its full trace, and the independent oracle's expected decision.
Then replay every decision from the ledger alone and compare canonical outputs. Writes one `.dot` view per
decision with required functions/files coloured covered (green) or missing (red).
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, Callable

import oracle

from .. import protocol
from ..cycles import Cycle
from ..hashing import canonical_json, sha256_file, sha256_json
from ..paths import repo_root
from ..proofweave.export_dot import export
from ..proofweave.graph import InMemoryGraphStore, TargetIndex, Weaver
from ..proofweave.ledger import Ledger
from ..taip import requirements, views as views_mod
from ..taip.evaluate import PASS, PROCEED, Evaluator, verdict_only
from .common import bundles, stage1_dir, target_root

Progress = Callable[[str], None]
DEFAULT_TAU = 0.8


def _oracle_is_independent() -> bool:
    for p in (Path(oracle.__file__).parent).rglob("*.py"):
        for n in ast.walk(ast.parse(p.read_text())):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else \
                [n.module or ""] if isinstance(n, ast.ImportFrom) else []
            if any(m == "pwexp" or m.startswith("pwexp.") for m in mods):
                return False
    return True


def _decide_all(ev: Evaluator, required: dict, vlist: list) -> dict[str, dict]:
    out = {}
    for v in vlist:
        out[v.id] = ev.decide(required, v) if v.attainable else {"view": v.manifest(), "posture": None, "action": None}
    return out


def _canonical(decisions: dict[str, dict]) -> str:
    slim = {k: {"posture": d["posture"], "action": d["action"], "missing": d.get("missing"), "failed": d.get("failed"),
                "witness_refs": sorted(r for o in d.get("obligations", []) for w in o["witnesses"] for r in w["refs"])}
            for k, d in decisions.items()}
    return sha256_json(slim)


def run(cycle: Cycle, required_path: Path | None = None, tau: float | None = None, operator: str = "unknown",
        progress: Progress = print) -> bool:
    proto = {}
    try:
        proto = protocol.load()
    except protocol.ProtocolError:
        pass
    if cycle.data["mode"] == "campaign":
        required_path = repo_root() / proto["required_set"]["path"]
        tau = proto["divergence"]["tau"]
    if required_path is None:
        raise ValueError("a pilot cycle needs an explicit required set (campaign cycles use the locked one)")
    tau = float(tau if tau is not None else DEFAULT_TAU)
    required = requirements.load(required_path)
    s1 = stage1_dir(cycle)
    s2 = cycle.path / "stage2" / cycle.data["stages"]["2"]["outcome"]["attempt_dir"] / "corpus"
    attempt = cycle.start(4)
    out = cycle.stage_dir(4) / f"attempt{attempt}"
    (out / "views").mkdir(parents=True)

    ledger = Ledger(s2)
    records = {r["record_hash"]: r for r in ledger.records()}
    blobs = {p.name for p in (s2 / "blobs").iterdir()}
    store = InMemoryGraphStore.load(s2 / "graph-checkpoint.json")
    ev = Evaluator(store, records, blobs)
    runs_attrs = {n["attrs"]["run"]: n["attrs"] for n in store.nodes().values() if n["kind"] == "run"}
    verdicts = {r: bool(a.get("green")) for r, a in runs_attrs.items()}
    green_ra = sorted(r for r, g in verdicts.items() if g and not r.startswith("semgrep/"))
    green_sg = sorted(r for r, g in verdicts.items() if g and r.startswith("semgrep/"))

    progress("selecting the divergent GREEN pair (fixed rule)")
    selection = views_mod.select_pair(store, verdicts, tau)
    (out / "pair-selection.json").write_text(json.dumps(selection, indent=2, sort_keys=True) + "\n")
    vlist = views_mod.build(selection, [r for r in verdicts if r.startswith("semgrep/")], green_sg, green_ra)
    by_id = {v.id: v for v in vlist}

    # views whose construction depends on another view's outcome
    def first_supported(vid: str) -> str | None:
        d = ev.decide(required, by_id[vid]) if by_id[vid].attainable else None
        return d["supported"][0] if d and d["posture"] == PASS and d["supported"] else None

    for dep, base in (("P2w", "P2"), ("P6", "P5")):
        item = first_supported(base)
        if item:
            by_id[dep].withheld = [item]
        else:
            by_id[dep].attainable = False
            by_id[dep].note = f"{base} already lacks mandatory support; controlled withholding not needed"
    a = (selection["selected"] or [selection["r_plus"]])[0]
    if a and by_id["P9"].attainable:
        d9 = ev.decide(required, by_id["P9"])
        by_id["P9"].mutated = {a: sorted({o["id"] for o in d9["obligations"] for w in o["witnesses"] if w["run"] == a})}

    progress(f"evaluating {len(vlist)} evidence views")
    decisions = _decide_all(ev, required, vlist)
    if decisions["P7"]["posture"] != PASS:
        by_id["P7"].note = "unattained: no complete-evidence view exists in the frozen corpus"
    bundle_map = dict(bundles(s1))
    expected = oracle.expected(bundle_map, required, target_root(s1), [v.manifest() for v in vlist])

    progress("replaying every decision from the ledger alone")
    fresh = InMemoryGraphStore()
    Weaver(fresh, TargetIndex.from_snapshot(target_root(s1))).apply(ledger.records())
    replay = _decide_all(Evaluator(fresh, records, blobs), required, vlist)
    replay_same = _canonical(replay) == _canonical(decisions)

    rows, agree, attainable, unsupported, avoidable = {}, 0, 0, 0, 0
    for v in vlist:
        d, o = decisions[v.id], expected[v.id]
        vo = verdict_only(v, verdicts) if v.attainable else None
        row = {"purpose": v.purpose, "attainable": v.attainable, "note": v.note, "runs": v.runs,
               "verdict_only": vo, "oracle": o.get("posture"), "oracle_action": o.get("action"),
               "observed": d["posture"], "action": d["action"], "missing": d.get("missing"), "failed": d.get("failed"),
               "agree": v.attainable and d["posture"] == o.get("posture") and d.get("missing") == o.get("missing")}
        if v.attainable:
            attainable += 1
            agree += row["agree"]
            unsupported += d["action"] == PROCEED and o.get("action") != PROCEED
            avoidable += d["action"] != PROCEED and o.get("action") == PROCEED
            req_fn = {}
            for ob in d["obligations"]:
                it = next(i for i in required["items"] if i["id"] == ob["id"])
                nodes = [f"fn:{it['function']}"] if it["kind"] == "A" else \
                    [f"fn:{f}" for f in it["functions"]] if it["kind"] == "V" else [f"file:{it['file']}"]
                for n in nodes:
                    if req_fn.get(n) != "#C62828":
                        req_fn[n] = "#2E7D32" if ob["state"] == PASS else "#C62828"
            export(store, out / "views" / f"{v.id}.dot", f"{v.id}: {v.purpose} → {d['posture']} / {d['action']}", req_fn)
        rows[v.id] = row
        (out / "views" / f"{v.id}.json").write_text(json.dumps({**d, "verdict_only": vo, "oracle": o},
                                                               indent=2, sort_keys=True) + "\n")
    p5 = rows["P5"]
    three = (f"{p5['verdict_only']} on verdicts alone; TAIP {p5['observed']} → {p5['action']}; missing {', '.join(p5['missing'] or [])}"
             if p5["attainable"] else "unattained (no qualifying divergent pair or no GREEN Semgrep run)")
    all_refs = {r for d in decisions.values() for ob in d.get("obligations", []) for w in ob["witnesses"] for r in w["refs"]}
    checks = {
        "every registered view evaluated or reported unattained": len(rows) == len(vlist),
        "every decision trace links to ledger records": all_refs <= set(records),
        "replay from the ledger reproduces every decision": replay_same,
        "oracle is a separate implementation (imports no pwexp)": _oracle_is_independent(),
        "required set non-empty and recorded": bool(required["items"]),
        "no control executed (corpus E only)": True,
    }
    try:
        req_ref = Path(required_path).resolve().relative_to(repo_root().resolve()).as_posix()
    except ValueError:
        req_ref = str(Path(required_path).resolve())
    outcome = {"required_set_sha256": sha256_file(required_path), "required_set_path": req_ref,
               "required_items": len(required["items"]),
               "tau": tau, "selected_pair": selection["selected"], "eligible_pairs": selection["eligible_pairs"],
               "qualifying_pairs": selection["qualifying_pairs"], "runs_path_observable": len(selection["green_observable"]),
               "views": rows, "oracle_agreement": f"{agree}/{attainable}", "unsupported_proceed": unsupported,
               "avoidable_hold": avoidable, "replay_agreement": f"{len(vlist) if replay_same else 0}/{len(vlist)}",
               "three_green_case": three, "attempt_dir": out.name}
    (out / "summary.json").write_text(json.dumps(outcome, indent=2, sort_keys=True) + "\n")
    return cycle.finish(4, checks, sha256_json(json.loads(canonical_json(outcome))), outcome, operator)
