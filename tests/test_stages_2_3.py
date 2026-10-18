"""Stages 2 and 3 on the imported fixture cycle (small repetitions and volumes for speed)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pwexp.importers import iceccs
from pwexp.proofweave.ledger import Ledger
from pwexp.stages import stage2_timing as s2
from pwexp.stages import stage3_scale as s3

FIX = Path(__file__).parent / "fixtures" / "iceccs-live-v1" / "python_npd"
RUNS = ["gpt-4.1/run15", "gpt-4.1/run25", "gpt-4o-mini/run01"]
QUIET = lambda m: None  # noqa: E731
TOY = Path(__file__).parents[1] / "vendor" / "RepoAudit" / "benchmark" / "Python" / "toy"
pytestmark = pytest.mark.skipif(not TOY.is_dir(), reason="RepoAudit submodule not initialised (target for entity resolution)")


def _link_target(root: Path) -> None:
    (root / "vendor" / "RepoAudit" / "benchmark" / "Python").mkdir(parents=True, exist_ok=True)
    link = root / "vendor" / "RepoAudit" / "benchmark" / "Python" / "toy"
    if not link.exists():
        link.symlink_to(TOY)


@pytest.fixture()
def cycle(tmp_path, monkeypatch):
    monkeypatch.setenv("PWEXP_ROOT", str(tmp_path))
    (tmp_path / "records" / "published").mkdir(parents=True)
    _link_target(tmp_path)
    return iceccs.import_cycle(FIX, RUNS)


def test_stage2_seals_authentic_deterministic_corpus(cycle):
    assert s2.run(cycle, repetitions=2, progress=QUIET)
    st = cycle.data["stages"]["2"]
    assert all(st["checks"].values()) and st["outcome"]["observations"] == 6
    out = cycle.path / "stage2" / "attempt1"
    man = json.loads((out / "corpus-manifest.json").read_text())
    assert man["corpus_sha256"] == st["outputs_manifest_sha256"] == st["outcome"]["corpus_sha256"]
    assert Ledger(out / "corpus").verify() == [] and (out / "corpus" / "graph.dot").exists()
    assert not (out / "rep01").exists() and not (out / "rep02").exists()
    assert cycle.next_stage() == 3


def test_stage2_gated_on_stage1(tmp_path, monkeypatch):
    from pwexp import cycles
    monkeypatch.setenv("PWEXP_ROOT", str(tmp_path))
    c = cycles.create("pilot", None)
    with pytest.raises(cycles.CycleError):
        c.start(2)


def test_stage3_synthetic_is_marked_distinct_and_segregated(cycle):
    s2.run(cycle, repetitions=1, progress=QUIET)
    assert s3.run(cycle, repetitions=2, volumes=[10, 200], progress=QUIET)
    st = cycle.data["stages"]["3"]
    assert all(st["checks"].values())
    vols = st["outcome"]["volumes"]
    assert vols["200"]["actual"][0] >= 200 and vols["10"]["actual"][0] >= 10
    lines = (cycle.path / "stage3" / "attempt1" / "timings.jsonl").read_text().splitlines()
    assert all(json.loads(l)["run"].startswith("syn-") for l in lines)
    corpus = (cycle.path / "stage2" / "attempt1" / "corpus" / "ledger.jsonl").read_text()
    assert '"synthetic": true' not in corpus
    assert cycle.next_stage() == 4


def test_synthetic_copies_have_distinct_bytes_same_meaning(tmp_path, cycle):
    from pwexp.hashing import sha256_file
    from pwexp.proofweave.adapters import repoaudit as ra
    src = sorted((cycle.path / "stage1" / "attempt1" / "repoaudit").glob("*/run*"))[0]
    a = s3.synthetic_bundle(src, tmp_path / "a", "syn-a")
    b = s3.synthetic_bundle(src, tmp_path / "b", "syn-b")
    assert all(sha256_file(a / f.name) != sha256_file(b / f.name) for f in src.iterdir() if f.is_file())
    assert [o.payload for o in ra.parse_run(a)[1]][1:] == [o.payload for o in ra.parse_run(src)[1]][1:]


def test_corpus_e_is_reproducible_across_cycles(tmp_path, monkeypatch):
    """Two independent cycles over the same evidence seal byte-identical corpora (reviewer replay, DR-17)."""
    monkeypatch.setenv("PWEXP_ROOT", str(tmp_path))
    (tmp_path / "records" / "published").mkdir(parents=True)
    _link_target(tmp_path)
    a, b = iceccs.import_cycle(FIX, RUNS), iceccs.import_cycle(FIX, RUNS)
    s2.run(a, repetitions=1, progress=QUIET)
    s2.run(b, repetitions=1, progress=QUIET)
    assert a.id != b.id
    assert a.data["stages"]["2"]["outcome"]["corpus_sha256"] == b.data["stages"]["2"]["outcome"]["corpus_sha256"]
