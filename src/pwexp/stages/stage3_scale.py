"""Stage 3: scale and threshold again (RQ2).

For each declared volume V (default 10, 100, 1,000, 10,000 records) and each repetition, a fresh
evidence plane is filled with synthetic bundles until the ledger holds at least V records; every
ingest is timed (t0..t4). The observation reported for (V, repetition) is the bundle that brought the
ledger to V or beyond, so it was written into a plane already holding about V records. Target and
actual record counts are both reported.

Synthetic bundles replay the sealed authentic bundles under new run identities, are bound with
`synthetic: true` (so they get distinct record ids and hashes) and live only in Stage 3's own planes,
segregated from corpus E. They model evidence-processing load, not additional control executions.
Each synthetic bundle carries its own distinct native bytes (a marker line before the first log entry,
trailing whitespace in JSON files), produced before t0 as a producer would, so the blob store cannot
deduplicate them: every synthetic ingest pays the full native-retention cost of new evidence.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Callable

from ..cycles import Cycle
from ..hashing import manifest_hash, sha256_bytes, sha256_file
from ..proofweave.graph import TargetIndex
from ..proofweave.ingress import EvidencePlane
from .common import bundles, stage1_dir, summary_ms, target_root, timing_params

Progress = Callable[[str], None]


def synthetic_bundle(src: Path, dst: Path, tag: str) -> Path:
    """Copy a bundle with distinct native bytes; semantics unchanged (outside the timed interval)."""
    dst.mkdir(parents=True)
    marker = f"# pwexp synthetic copy {tag}\n".encode()
    for f in src.iterdir():
        if not f.is_file():
            continue
        data = f.read_bytes()
        if f.suffix in (".log",):
            data = marker + data                     # before the first entry: ignored by the adapter
        elif f.suffix in (".json", ".jsonl"):
            bits = bin(int(sha256_bytes(tag.encode())[:16], 16))[2:].zfill(64)
            data = data + b"\n" + "".join(" " if c == "0" else "\t" for c in bits).encode() + b"\n"
            if f.name == "manifest.json":
                doc = json.loads(f.read_bytes())
                doc["synthetic_copy_of"] = tag
                data = json.dumps(doc, indent=2, sort_keys=True).encode() + b"\n"
        (dst / f.name).write_bytes(data)
    return dst


def run(cycle: Cycle, repetitions: int | None = None, volumes: list[int] | None = None,
        operator: str = "unknown", progress: Progress = print) -> bool:
    params = timing_params(cycle)
    reps = repetitions or int(params["repetitions"])
    vols = sorted(int(v) for v in (volumes or params["volumes"]))
    threshold_ns = int(float(params["reference_threshold_s"]) * 1e9)
    s1 = stage1_dir(cycle)
    work = bundles(s1)
    if not work:
        raise ValueError("no sealed Stage 1 bundles to replay")
    index = TargetIndex.from_snapshot(target_root(s1))
    attempt = cycle.start(3)
    out = cycle.stage_dir(3) / f"attempt{attempt}"
    out.mkdir(parents=True)
    rows, sums_ok, all_ready, synthetic_ok = {}, True, True, True
    with (out / "timings.jsonl").open("w") as f:
        for v in vols:
            crossing = []
            for r in range(1, reps + 1):
                plane_dir = out / f"v{v}-rep{r:02d}"
                plane = EvidencePlane(plane_dir, index, params["durability"])
                k = 0
                while plane.ledger.head[0] + 1 < v:
                    tag, b = work[k % len(work)]
                    k += 1
                    run_tag = f"syn-v{v}-r{r}-b{k:05d}:{tag}"
                    sb = synthetic_bundle(b, out / "tmp" / f"b{k:05d}", run_tag)
                    t = plane.ingest(sb, run_tag, {"repo": "synthetic", "commit": "", "synthetic": True})
                    shutil.rmtree(sb)
                    t.update(volume=v, repetition=r, bundle=k, records_after=plane.ledger.head[0] + 1,
                             within_threshold=t["T_ready_ns"] <= threshold_ns)
                    sums_ok &= sum(t["components_ns"].values()) == t["T_ready_ns"]
                    all_ready &= t["ready"]
                    f.write(json.dumps(t, sort_keys=True) + "\n")
                    last = t
                crossing.append(last)
                synthetic_ok &= all(r_.get("synthetic") for r_ in plane.ledger.records())
                shutil.rmtree(plane_dir)  # measurement scratch; timings are retained
            ts = [c["T_ready_ns"] for c in crossing]
            rows[str(v)] = {"target": v, "actual": [c["records_after"] for c in crossing], "repetitions": reps,
                            **summary_ms(ts), "within_threshold": sum(c["within_threshold"] for c in crossing),
                            "exceedances": sum(not c["within_threshold"] for c in crossing),
                            "not_ready": sum(not c["ready"] for c in crossing)}
            progress(f"volume {v:>6}: median {rows[str(v)]['median_ms']} ms · max {rows[str(v)]['max_ms']} ms "
                     f"· actual {rows[str(v)]['actual'][0]} records")
    (out / "summary.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")
    crossing_at = next((int(v) for v in rows if rows[v]["exceedances"]), None)
    checks = {
        "every volume point measured in every repetition": all(len(r["actual"]) == reps for r in rows.values()),
        "every synthetic bundle became queryable": all_ready,
        "components sum to t4 − t0 for every observation": sums_ok,
        "every synthetic record marked and kept out of corpus E": synthetic_ok,
    }
    outcome = {"volumes": rows, "repetitions": reps, "threshold_s": float(params["reference_threshold_s"]),
               "largest_volume": max(vols), "max_ready_ms_at_largest": rows[str(max(vols))]["max_ms"],
               "threshold_crossing": f"at {crossing_at} records" if crossing_at else "none in tested range",
               "attempt_dir": out.name}
    return cycle.finish(3, checks, manifest_hash({"timings.jsonl": sha256_file(out / "timings.jsonl"),
                                                   "summary.json": sha256_file(out / "summary.json")}),
                        outcome, operator)
