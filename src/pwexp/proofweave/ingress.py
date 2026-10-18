"""Evidence plane ingress: receive a native bundle and time it to query-readiness (RQ2).

  t0  bundle received at ingress (native bytes are read after t0, so parsing is measured)
  t1  adapter + Bind complete
  t2  ledger append acknowledged (declared durability)
  t3  Graph Weaver materialisation complete
  t4  readiness probe confirms the bundle's records are queryable at the committed watermark
Monotonic clock: time.perf_counter_ns(). Producer execution and transport are outside the interval.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .adapters import repoaudit as ra_adapter
from .adapters import semgrep as sg_adapter
from .bind import BindContext, bind
from .graph import InMemoryGraphStore, TargetIndex, Weaver
from .ledger import Ledger
from .query import QueryAPI


class EvidencePlane:
    def __init__(self, path: Path, index: TargetIndex | None = None, durability: str = "fsync-per-bundle"):
        self.path = Path(path)
        self.ledger = Ledger(self.path, durability)
        self.store = InMemoryGraphStore()
        self.weaver = Weaver(self.store, index or TargetIndex())
        self.query = QueryAPI(self.store)
        self.weaver.apply(self.ledger.records())  # resume from an existing ledger

    def ingest(self, bundle: Path, run: str, ctx_base: dict[str, Any]) -> dict[str, Any]:
        """Ingest one native run bundle; return timings in nanoseconds and record counts."""
        bundle = Path(bundle)
        t0 = time.perf_counter_ns()
        man = json.loads((bundle / "manifest.json").read_bytes())
        if man.get("control") == "semgrep":
            _, obs = sg_adapter.parse_run(bundle)
            root = ctx_base.get("project_root")
        else:
            man, obs = ra_adapter.parse_run(bundle)
            root = ra_adapter.project_root_of(man) or ctx_base.get("project_root")
        ctx = BindContext(run=run, repo=ctx_base.get("repo", ""), commit=ctx_base.get("commit", ""),
                          project_root=root, config={"provider": man.get("provider"), "model": man.get("requested_model"),
                                                     "temperature": man.get("temperature"), **ctx_base.get("config", {})},
                          collection_policy=ctx_base.get("collection_policy"),
                          completion="complete" if man.get("complete", man.get("exit_code") == 0) else "incomplete",
                          synthetic=ctx_base.get("synthetic", False))
        records = bind(obs, ctx)
        blobs = {f.name: f.read_bytes() for f in bundle.iterdir() if f.is_file()}
        t1 = time.perf_counter_ns()
        for data in blobs.values():
            self.ledger.put_blob(data)
        appended = self.ledger.append_batch(records)
        t2 = time.perf_counter_ns()
        self.weaver.apply(appended)
        t3 = time.perf_counter_ns()
        ready = self.query.probe([r["record_hash"] for r in appended], self.ledger.head[0])
        t4 = time.perf_counter_ns()
        return {"run": run, "records": len(appended), "ready": ready,
                "t_ns": {"t1": t1 - t0, "t2": t2 - t0, "t3": t3 - t0, "t4": t4 - t0},
                "components_ns": {"bind": t1 - t0, "ledger": t2 - t1, "weave": t3 - t2, "query_ready": t4 - t3},
                "T_ready_ns": t4 - t0, "watermark": self.ledger.head[0]}

    def checkpoint(self) -> str:
        return self.store.checkpoint(self.path / "graph-checkpoint.json")

    def rebuild_hash(self) -> str:
        """Graph hash rebuilt from the ledger alone (determinism check)."""
        s = InMemoryGraphStore()
        Weaver(s, self.weaver.index).apply(self.ledger.records())
        return s.graph_hash()
