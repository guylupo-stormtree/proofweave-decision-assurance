"""Stage 4 (Three GREENs, not enough coverage): natural HOLD, PASS path, FAIL path, admission, oracle, replay."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pwexp.importers import devfixture, iceccs
from pwexp.stages import stage2_timing as s2
from pwexp.stages import stage3_scale as s3
from pwexp.stages import stage4_decisions as s4
from pwexp.taip.requirements import draft

DEV = Path(__file__).parent / "fixtures" / "dev-guarded-users"
RUNS = ["guarded-users/gpt-local-qwen3b/run02", "guarded-users/gpt-local-qwen3b/run04",
        "guarded-users/gpt-local-qwen3b/run06", "guarded-users-t05/gpt-local-qwen3b/run01",
        "guarded-users-t05/gpt-local-qwen3b/run05"]
TOY = Path(__file__).parents[1] / "vendor" / "RepoAudit" / "benchmark" / "Python" / "toy"
QUIET = lambda m: None  # noqa: E731


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("PWEXP_ROOT", str(tmp_path))
    (tmp_path / "records" / "published").mkdir(parents=True)
    # the dev cycle's plan refers to targets/fixture-guarded-users under the repository root
    (tmp_path / "targets").mkdir()
    (tmp_path / "targets" / "fixture-guarded-users").symlink_to(Path(__file__).parents[1] / "targets" / "fixture-guarded-users")
    if TOY.is_dir():  # imported first-study cycles refer to vendor/RepoAudit/benchmark/Python/toy
        (tmp_path / "vendor" / "RepoAudit" / "benchmark" / "Python").mkdir(parents=True)
        (tmp_path / "vendor" / "RepoAudit" / "benchmark" / "Python" / "toy").symlink_to(TOY)
    return tmp_path


def _through_stage3(c):
    assert s2.run(c, repetitions=1, progress=QUIET)
    assert s3.run(c, repetitions=1, volumes=[10], progress=QUIET)
    return c


def _dev_cycle():
    return _through_stage3(devfixture.import_cycle(DEV, RUNS, semgrep=["semgrep/run001"]))


def test_natural_three_greens_hold(root):
    c = _dev_cycle()
    assert s4.run(c, required_path=DEV / "required-set.json", progress=QUIET)
    o = c.data["stages"]["4"]["outcome"]
    assert all(c.data["stages"]["4"]["checks"].values()) and c.data["status"] == "complete"
    p5 = o["views"]["P5"]
    assert p5["verdict_only"] == "PROCEED" and p5["observed"] == "INCONCLUSIVE" and p5["action"] == "HOLD"
    assert p5["agree"] and p5["missing"]
    n, d = map(int, o["oracle_agreement"].split("/"))
    assert n == d > 0 and o["unsupported_proceed"] == 0 and o["replay_agreement"] == "11/11"
    assert not o["views"]["P6"]["attainable"]          # P5 already insufficient: no withholding needed
    assert (c.path / "stage4" / "attempt1" / "views" / "P5.dot").exists()


def test_pass_path_and_controlled_withholding(root, tmp_path):
    full = json.loads((DEV / "required-set.json").read_text())
    covered = {**full, "items": [i for i in full["items"] if i["kind"] in ("A", "S")]}
    req = tmp_path / "covered.json"
    req.write_text(json.dumps(covered))
    c = _dev_cycle()
    assert s4.run(c, required_path=req, progress=QUIET)
    v = c.data["stages"]["4"]["outcome"]["views"]
    assert v["P5"]["observed"] == "PASS" and v["P5"]["action"] == "PROCEED" and v["P5"]["agree"]
    assert v["P6"]["attainable"] and v["P6"]["observed"] == "INCONCLUSIVE" and v["P6"]["agree"]
    assert v["P7"]["observed"] == "PASS"
    assert v["P2"]["observed"] == "INCONCLUSIVE"         # RepoAudit alone cannot satisfy the Semgrep scan items
    assert v["P3"]["observed"] == "PASS"                 # heterogeneous composition completes it


def test_mutated_and_incompatible_witnesses_are_rejected(root):
    c = _dev_cycle()
    s4.run(c, required_path=DEV / "required-set.json", progress=QUIET)
    views = c.path / "stage4" / "attempt1" / "views"
    p9 = json.loads((views / "P9.json").read_text())
    p8 = json.loads((views / "P8.json").read_text())
    assert any(r["reason"].startswith("integrity") for o in p9["obligations"] for r in o["rejected"])
    assert any(r["reason"] == "incompatible context" for o in p8["obligations"] for r in o["rejected"])
    a = p8["view"]["incompatible_runs"][0]
    assert not any(w["run"] == a for o in p8["obligations"] for w in o["witnesses"])


@pytest.mark.skipif(not TOY.is_dir(), reason="RepoAudit submodule not initialised")
def test_fail_path_on_reported_findings(root, tmp_path):
    fix = Path(__file__).parent / "fixtures" / "iceccs-live-v1" / "python_npd"
    c = _through_stage3(iceccs.import_cycle(fix, ["gpt-4.1/run25", "gpt-4o-mini/run01"]))
    req = tmp_path / "toy.json"
    req.write_text(json.dumps(draft(TOY)))
    assert s4.run(c, required_path=req, progress=QUIET)
    o = c.data["stages"]["4"]["outcome"]
    assert o["selected_pair"] is None and o["three_green_case"].startswith("unattained")
    p7 = o["views"]["P7"]
    assert p7["runs"] == [] and p7["observed"] == "INCONCLUSIVE"   # no GREEN run: nothing to compose
    n, d = map(int, o["oracle_agreement"].split("/"))
    assert n == d
    # an explicit adverse view: a run that reported findings on required functions must FAIL (paper Eq. obligation-state)
    import oracle
    from pwexp.proofweave.graph import InMemoryGraphStore
    from pwexp.proofweave.ledger import Ledger
    from pwexp.stages.common import bundles, stage1_dir
    from pwexp.taip.evaluate import Evaluator, View
    corpus = c.path / "stage2" / "attempt1" / "corpus"
    ev = Evaluator(InMemoryGraphStore.load(corpus / "graph-checkpoint.json"),
                   {r["record_hash"]: r for r in Ledger(corpus).records()}, {b.name for b in (corpus / "blobs").iterdir()})
    required = json.loads(req.read_text())
    view = View("adverse", ["gpt-pw-m1/run001"], "run reporting findings")
    got = ev.decide(required, view)
    want = oracle.expected(dict(bundles(stage1_dir(c))), required, TOY, [view.manifest()])["adverse"]
    assert got["posture"] == want["posture"] == "FAIL" and got["action"] == "HOLD"
    assert got["failed"] and all(v["finding"] for o in got["obligations"] if o["state"] == "FAIL" for v in o["violations"])


def test_pilot_needs_explicit_required_set(root):
    c = _dev_cycle()
    with pytest.raises(ValueError):
        s4.run(c, progress=QUIET)
