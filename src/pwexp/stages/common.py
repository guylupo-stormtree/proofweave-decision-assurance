"""Helpers shared by Stages 2-4: locating sealed Stage 1 evidence and protocol defaults."""
from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any

from .. import protocol
from ..cycles import Cycle, load
from ..paths import repo_root

DEFAULTS = {"reference_threshold_s": 5.0, "repetitions": 5, "volumes": [10, 100, 1000, 10000],
            "durability": "fsync-per-bundle"}


def timing_params(cycle: Cycle) -> dict[str, Any]:
    """Locked protocol values for a campaign; protocol values (if complete) or defaults for pilots."""
    try:
        t = protocol.load().get("timing", {})
    except protocol.ProtocolError:
        t = {}
    if cycle.data["mode"] == "campaign" and any(protocol._unset(t.get(k)) for k in DEFAULTS):
        raise ValueError("campaign cycle: timing parameters must be set in the locked protocol")
    return {k: (DEFAULTS[k] if protocol._unset(t.get(k)) else t[k]) for k in DEFAULTS}


def stage1_dir(cycle: Cycle) -> Path:
    """The sealed Stage 1 attempt directory (own, or the published cycle this replay cycle reads)."""
    st = cycle.data["stages"]["1"]
    src = st.get("source", "")
    if src.startswith("published:"):
        pub = load(src.split(":", 1)[1])
        return pub.path / "stage1" / pub.data["stages"]["1"]["outcome"]["attempt_dir"]
    return cycle.path / "stage1" / st["outcome"]["attempt_dir"]


def bundles(s1: Path) -> list[tuple[str, Path]]:
    """(run tag, bundle dir) for every retained RepoAudit and Semgrep run, in deterministic order."""
    out = [(f"{p.parent.name}/{p.name}", p) for p in sorted((s1 / "repoaudit").glob("*/run*"))]
    out += [(f"semgrep/{p.name}", p) for p in sorted((s1 / "semgrep").glob("run*"))]
    return out


def target_root(s1: Path) -> Path | None:
    plan = json.loads((s1 / "plan.json").read_text()) if (s1 / "plan.json").exists() else {}
    t = plan.get("target")
    if not t:
        return None
    p = Path(t)
    return p if p.is_absolute() else repo_root() / p


def summary_ms(values_ns: list[int]) -> dict[str, float | None]:
    if not values_ns:
        return {"median_ms": None, "min_ms": None, "max_ms": None}
    ms = [v / 1e6 for v in values_ns]
    return {"median_ms": round(statistics.median(ms), 3), "min_ms": round(min(ms), 3), "max_ms": round(max(ms), 3)}
