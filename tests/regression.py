"""Shared builder for the PW-REG-1 regression guard: corpus identity of the development fixtures."""
from __future__ import annotations

from pathlib import Path

from pwexp.importers import devfixture, iceccs
from pwexp.stages import stage2_timing

FIX = Path(__file__).parent / "fixtures"
DEV_RUNS = ["guarded-users/gpt-local-qwen3b/run02", "guarded-users/gpt-local-qwen3b/run04",
            "guarded-users/gpt-local-qwen3b/run06", "guarded-users-t05/gpt-local-qwen3b/run01",
            "guarded-users-t05/gpt-local-qwen3b/run05"]
ICECCS_RUNS = ["gpt-4.1/run01", "gpt-4.1/run15", "gpt-4.1/run25", "gpt-4.1/run28", "gpt-4o-mini/run01"]


def identity(cycle) -> dict:
    assert stage2_timing.run(cycle, repetitions=1, progress=lambda m: None)
    o = cycle.data["stages"]["2"]["outcome"]
    import json
    man = json.loads((cycle.path / "stage2" / o["attempt_dir"] / "corpus-manifest.json").read_text())
    return {"ledger_head": man["ledger_head"], "graph_sha256": o["graph_sha256"], "corpus_sha256": o["corpus_sha256"],
            "records": o["records"]}


def build_all() -> dict:
    dev = devfixture.import_cycle(FIX / "dev-guarded-users", DEV_RUNS, semgrep=["semgrep/run001"])
    ice = iceccs.import_cycle(FIX / "iceccs-live-v1" / "python_npd", ICECCS_RUNS)
    return {"dev-guarded-users": identity(dev), "iceccs-live-v1": identity(ice)}
