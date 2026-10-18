"""Stage 2: ProofWeave within the threshold (RQ2).

Replays every sealed Stage 1 bundle into a freshly reset evidence plane, once per declared repetition,
and records t0..t4 per bundle (evidence-write request received → queryable for posture calculation).
Each observation is compared with the reference threshold B_ref: Δ_ready = B_ref − T_PW-ready.
Exceeding the threshold is a reported outcome, not a stage failure.

The first repetition's plane, built from authentic evidence only, is sealed as corpus E (ledger,
native blobs, graph checkpoint, .dot export). Stage 4 evaluates every decision over corpus E.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Callable

from ..cycles import Cycle
from ..hashing import manifest_hash, tree_manifest
from ..proofweave.export_dot import export
from ..proofweave.graph import TargetIndex
from ..proofweave.ingress import EvidencePlane
from ..proofweave.ledger import Ledger
from .common import bundles, stage1_dir, summary_ms, target_root, timing_params

Progress = Callable[[str], None]


def run(cycle: Cycle, repetitions: int | None = None, operator: str = "unknown", progress: Progress = print) -> bool:
    params = timing_params(cycle)
    reps = repetitions or int(params["repetitions"])
    threshold_ns = int(float(params["reference_threshold_s"]) * 1e9)
    s1 = stage1_dir(cycle)
    work = bundles(s1)
    if not work:
        raise ValueError("no sealed Stage 1 bundles to replay")
    troot = target_root(s1)
    index = TargetIndex.from_snapshot(troot)
    ctx_base = {"repo": cycle.data.get("target_repo", "target"), "commit": cycle.data.get("target_commit", ""),
                "collection_policy": cycle.data.get("protocol_lock_sha256")}
    attempt = cycle.start(2)
    out = cycle.stage_dir(2) / f"attempt{attempt}"
    out.mkdir(parents=True)
    obs, hashes, all_ready, sums_ok = [], [], True, True
    with (out / "timings.jsonl").open("w") as f:
        for r in range(1, reps + 1):
            plane = EvidencePlane(out / f"rep{r:02d}", index, params["durability"])
            for k, (tag, b) in enumerate(work, 1):
                t = plane.ingest(b, tag, ctx_base)
                t.update(repetition=r, bundle=k, within_threshold=t["T_ready_ns"] <= threshold_ns,
                         delta_ready_ns=threshold_ns - t["T_ready_ns"])
                all_ready &= t["ready"]
                sums_ok &= sum(t["components_ns"].values()) == t["T_ready_ns"]
                obs.append(t)
                f.write(json.dumps(t, sort_keys=True) + "\n")
            hashes.append(plane.store.graph_hash())
            progress(f"repetition {r}/{reps}: {len(work)} bundles · median "
                     f"{summary_ms([o['T_ready_ns'] for o in obs if o['repetition'] == r])['median_ms']} ms")
            if r == 1:
                corpus_plane = plane
    # seal corpus E from the authentic first repetition
    corpus = out / "corpus"
    shutil.copytree(out / "rep01", corpus)
    graph_hash = corpus_plane.checkpoint()
    shutil.copy2(out / "rep01" / "graph-checkpoint.json", corpus / "graph-checkpoint.json")
    rebuild_ok = corpus_plane.rebuild_hash() == graph_hash
    bed = cycle.data["stages"]["1"].get("outputs_manifest_sha256") or "published"
    export(corpus_plane.store, corpus / "graph.dot", f"corpus E · evidence bed {str(bed)[:12]}")  # content-derived
    for r in range(2, reps + 1):  # repetition planes are measurement scratch; keep only their timings
        shutil.rmtree(out / f"rep{r:02d}")
    shutil.rmtree(out / "rep01")  # identical to corpus/, which is the sealed copy
    files = tree_manifest(corpus)
    corpus_hash = manifest_hash(files)
    (out / "corpus-manifest.json").write_text(json.dumps(
        {"cycle": cycle.id, "files": files, "corpus_sha256": corpus_hash, "graph_sha256": graph_hash,
         "ledger_head": corpus_plane.ledger.head, "records": corpus_plane.ledger.head[0] + 1}, indent=2, sort_keys=True) + "\n")
    t_all = [o["T_ready_ns"] for o in obs]
    comps = {c: summary_ms([o["components_ns"][c] for o in obs]) for c in ("bind", "ledger", "weave", "query_ready")}
    checks = {
        "every bundle became queryable in every repetition": all_ready,
        "components sum to t4 − t0 for every observation": sums_ok,
        "identical graph in every repetition (determinism)": len(set(hashes)) == 1,
        "graph rebuilt from the ledger equals the checkpoint": rebuild_ok,
        "sealed corpus ledger intact": not Ledger(corpus).verify(),
        "target snapshot available for entity resolution": bool(troot and troot.is_dir() and index.functions),
        "corpus E sealed from authentic evidence only": not any('"synthetic": true' in l for l in
                                                               (corpus / "ledger.jsonl").read_text().splitlines()),
    }
    outcome = {"bundles": len(work), "repetitions": reps, "observations": len(obs),
               "threshold_s": float(params["reference_threshold_s"]), **summary_ms(t_all),
               "within_threshold": sum(o["within_threshold"] for o in obs), "components": comps,
               "corpus_sha256": corpus_hash, "graph_sha256": graph_hash, "records": corpus_plane.ledger.head[0] + 1,
               "graph_nodes": len(corpus_plane.store.nodes()), "graph_edges": len(corpus_plane.store.edges()),
               "unresolved_functions": sorted(n["id"] for n in corpus_plane.store.nodes().values()
                                              if n["kind"] == "function" and not n["attrs"].get("resolved")),
               "durability": params["durability"], "attempt_dir": out.name}
    return cycle.finish(2, checks, corpus_hash, outcome, operator)
