"""ProofWeave core (P2) on real RepoAudit runs from the first study's public dataset (fixtures)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pwexp.importers import iceccs
from pwexp.proofweave.adapters import repoaudit as ra
from pwexp.proofweave.bind import BindContext, bind
from pwexp.proofweave.graph import InMemoryGraphStore, TargetIndex
from pwexp.proofweave.ingress import EvidencePlane
from pwexp.proofweave.ledger import Ledger

FIX = Path(__file__).parent / "fixtures" / "iceccs-live-v1" / "python_npd"
RUNS = ["gpt-4.1/run01", "gpt-4.1/run15", "gpt-4.1/run25", "gpt-4.1/run28", "gpt-4o-mini/run01"]
TOY = Path(__file__).parents[1] / "vendor" / "RepoAudit" / "benchmark" / "Python" / "toy"
needs_toy = pytest.mark.skipif(not TOY.is_dir(), reason="RepoAudit submodule not initialised")


@pytest.fixture()
def cycle(tmp_path, monkeypatch):
    monkeypatch.setenv("PWEXP_ROOT", str(tmp_path))
    (tmp_path / "records" / "published").mkdir(parents=True)
    return iceccs.import_cycle(FIX, RUNS)


def _runs(cycle):
    return sorted((cycle.path / "stage1" / "attempt1" / "repoaudit").glob("*/run*"))


@pytest.fixture()
def plane(cycle, tmp_path):
    p = EvidencePlane(tmp_path / "plane", TargetIndex.from_snapshot(TOY))
    timings = [p.ingest(r, f"{r.parent.name}/{r.name}", {"repo": "toy", "commit": "160f5bc"}) for r in _runs(cycle)]
    return p, timings


# ------------------------------------------------------------------ adapter
def test_source_refs_point_at_exact_log_entries():
    data = (FIX / "gpt-4.1/run25" / "dfbscan.log").read_bytes()
    obs = ra.parse_log(data)
    assert obs and all(data[o.source_ref["start"]:o.source_ref["end"]][:2] == b"20" for o in obs)
    units = [o for o in obs if o.event_type == "repoaudit.analysis_unit"]
    for o in units:
        entry = data[o.source_ref["start"]:o.source_ref["end"]].decode()
        assert "Prompt:" in entry and str(o.payload["line"]) in entry


def test_counts_consistent_with_repoaudit_behaviour():
    for r in RUNS:
        kinds = [o.event_type for o in ra.parse_log((FIX / r / "dfbscan.log").read_bytes())]
        assert kinds.count("repoaudit.validation_request") == kinds.count("repoaudit.validation_answer")
        assert kinds.count("repoaudit.analysis_unit") >= 1


# ------------------------------------------------------------------ bind
def test_bind_privacy_and_deterministic_ids(cycle):
    run = _runs(cycle)[0]
    man, obs = ra.parse_run(run)
    ctx = BindContext("gpt-pw-m1/run001", "toy", "160f5bc", ra.project_root_of(man))
    recs = bind(obs, ctx)
    assert "/Users/" not in json.dumps([r["payload"] for r in recs])
    assert [r["id"] for r in recs] == [r["id"] for r in bind(obs, ctx)]
    assert len({r["id"] for r in recs}) == len(recs)
    syn = bind(obs, BindContext("gpt-pw-m1/run001", "toy", "160f5bc", ra.project_root_of(man), synthetic=True))
    assert not {r["id"] for r in recs} & {r["id"] for r in syn} and all(r["synthetic"] for r in syn)


# ------------------------------------------------------------------ ledger
def test_ledger_detects_alteration_and_missing_blob(plane):
    p, _ = plane
    assert p.ledger.verify() == []
    lines = p.ledger.file.read_text().splitlines()
    rec = json.loads(lines[3])
    rec["payload"] = {"forged": True}
    lines[3] = json.dumps(rec, sort_keys=True)
    p.ledger.file.write_text("\n".join(lines) + "\n")
    assert any("altered" in x for x in Ledger(p.path).verify())


def test_ledger_detects_missing_native_blob(plane):
    p, _ = plane
    next((p.path / "blobs").iterdir()).unlink()
    assert any("blob" in x for x in p.ledger.verify())


# ------------------------------------------------------------------ graph + query
@needs_toy
def test_graph_rebuild_and_checkpoint_roundtrip(plane):
    p, _ = plane
    h = p.checkpoint()
    assert h == p.rebuild_hash()
    assert InMemoryGraphStore.load(p.path / "graph-checkpoint.json").graph_hash() == h
    assert not [n for n in p.store.nodes().values() if n["kind"] == "function" and not n["attrs"]["resolved"]]


@needs_toy
def test_model_dependent_coverage_is_visible(plane):
    p, _ = plane
    chain = {"kind": "V", "functions": ["NPD/case04.py::test4_test", "NPD/case04.py::test4_inner_call"]}
    runs = {w["run"] for w in p.query.witnesses(chain)}
    assert runs == {"gpt-pw-m1/run001", "gpt-pw-m1/run002", "gpt-pw-m1/run003", "gpt-pw-m1/run004"}
    assert not p.query.witnesses(chain, runs=["gpt-pw-m2/run001"])          # gpt-4o-mini never built it
    unit = {"kind": "A", "function": "NPD/case04.py::test4_middle_call"}
    assert p.query.witnesses(unit, runs=["gpt-pw-m2/run001"])               # but it did analyse the unit
    assert all(w["refs"] for w in p.query.witnesses(chain))


def test_probe_and_timing_arithmetic(plane):
    p, timings = plane
    for t in timings:
        assert t["ready"] and t["records"] > 0
        assert sum(t["components_ns"].values()) == t["T_ready_ns"] == t["t_ns"]["t4"]
    assert not p.query.probe(["not-a-record"], p.ledger.head[0])
