"""Decision binding (DR-23): bundles, protocol, Stage 1 schedule, ingest, queries, failure handling."""
from __future__ import annotations

import json
import os
import shutil
import signal
from pathlib import Path

import pytest

from pwexp import protocol
from pwexp.importers import devfixture
from pwexp.proofweave import decision_bundle as db
from pwexp.proofweave.export_dot import export_decision
from pwexp.proofweave.graph import InMemoryGraphStore
from pwexp.proofweave.ingress import DecisionIngestError, EvidencePlane
from pwexp.proofweave.ledger import Ledger
from pwexp.proofweave.query import QueryAPI
from pwexp.stages import stage1_acquire as s1
from pwexp.stages import stage2_timing as s2
from pwexp.stages.common import bundles, stage1_dir

FIX = Path(__file__).parent / "fixtures" / "dev-guarded-users"
DPROTO = FIX / "decisions" / "protocol.yaml"
RUNS = ["guarded-users/gpt-local-qwen3b/run02", "guarded-users/gpt-local-qwen3b/run04",
        "guarded-users/gpt-local-qwen3b/run06", "guarded-users-t05/gpt-local-qwen3b/run01",
        "guarded-users-t05/gpt-local-qwen3b/run05"]
QUIET = lambda m: None  # noqa: E731
INTENT = {"intent_id": "i-1", "action": "release", "repo": "r", "commit": "c", "bug_type": "NPD",
          "scope_ref": {"file": "m.json", "sha256": "0" * 64}, "requested_by": "t", "created_at": "now"}


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("PWEXP_ROOT", str(tmp_path))
    monkeypatch.setenv("PWEXP_PROTOCOL", str(DPROTO))
    (tmp_path / "records" / "published").mkdir(parents=True)
    (tmp_path / "targets").mkdir()
    (tmp_path / "targets" / "fixture-guarded-users").symlink_to(Path(__file__).parents[1] / "targets" / "fixture-guarded-users")
    (tmp_path / "tests").symlink_to(Path(__file__).parent)   # `pwexp import-dev` reads the fixture from the root
    return tmp_path


def _dev_cycle():
    proto = protocol.load()
    return devfixture.import_cycle(FIX, RUNS, semgrep=["semgrep/run001"], decisions=proto, base=protocol.base_dir())


def _corpus(c):
    assert s2.run(c, repetitions=1, progress=QUIET)
    d = c.path / "stage2" / c.data["stages"]["2"]["outcome"]["attempt_dir"] / "corpus"
    store = InMemoryGraphStore.load(d / "graph-checkpoint.json")
    return d, store, QueryAPI(store, Ledger(d))


# ---------------------------------------------------------------- bundles and protocol
def test_bundle_roundtrip_and_tamper(tmp_path):
    b = tmp_path / "d1"
    db.write_context(b, "d1", "repoaudit", "v", INTENT, "P1", 1, b'{"b": 1, "a": 2}', ["m/run001"], "DR-11")
    assert (b / "policy" / "P1@1.json").read_bytes() == b'{"a":2,"b":1}'           # canonical JSON
    with pytest.raises(db.DecisionBundleError):
        db.write_decision(b, {"m/run001": True, "x/run009": True}, "h")              # not the planned basis
    dec = db.write_decision(b, {"m/run001": True}, "h")
    assert dec["verdict"] == "green" and db.load(b)["context"]["policy_ref"]["file"] == "policy/P1@1.json"
    (b / "policy" / "P1@1.json").write_bytes(b'{"a":3,"b":1}')
    with pytest.raises(db.DecisionBundleError):
        db.load(b)
    with pytest.raises(db.DecisionBundleError):
        db.decide("DR-11", {"a": True, "b": True})                                  # DR-11 is single-run
    assert db.decide("all-green", {"a": True, "b": False}) == "not_green"


def test_decision_protocol_check_and_lock(tmp_path):
    work = tmp_path / "p"
    shutil.copytree(DPROTO.parent, work)
    (work / "protocol.yaml").write_text(DPROTO.read_text().replace("../../../../", str(Path(__file__).parents[1]) + "/"))
    proto = protocol.load(work / "protocol.yaml")
    assert protocol.is_decision_protocol(proto) and protocol.problems(proto, work) == []
    doc = protocol.lock(work / "protocol.yaml", work)
    assert set(doc["files"]) >= {"protocol.yaml", "manifests/M_h.json", "policies/P1@1.json", "policies/P2@1.json"}
    assert protocol.check_lock(work / "protocol.yaml", work)[0]
    (work / "policies" / "P1@1.json").write_text("{}")
    ok, why = protocol.check_lock(work / "protocol.yaml", work)
    assert not ok and "P1@1" in why
    bad = dict(proto, decisions={**proto["decisions"], "groups": [{"group": "G-x", "basis": ["repoaudit", "semgrep"],
                                                                     "policy": "P9@1", "rule": "DR-11", "count": 0}]})
    errs = " ".join(protocol.problems(bad, work))
    assert "P9@1" in errs and "exactly one basis run" in errs and "count" in errs


def test_schedule_is_seeded_and_complete():
    groups = protocol.load(DPROTO)["decisions"]
    a, b = s1.schedule(groups, 7), s1.schedule(groups, 7)
    assert a == b and sorted(d["decision_id"] for d in a) == ["G-main-01", "G-main-02", "G-main-03", "G-pipe-01",
                                                              "G-strict-01"]
    assert s1.schedule(groups, 8) != a or len(a) < 3


# ---------------------------------------------------------------- Stage 1 decision schedule (control faked)
class _FakeGateway:
    def __init__(self, models):
        self.models, self.calls = models, []

    def start(self):
        pass

    def stop(self):
        pass

    def mark(self, tag):
        pass

    def calls_for(self, tag):
        return []

    def child_env(self):
        return {}


def test_stage1_writes_context_before_runs_and_decision_after(root, monkeypatch):
    from pwexp import cycles
    from pwexp.models import RunModels
    src = {"repoaudit": FIX / RUNS[0], "semgrep": FIX / "semgrep" / "run001"}

    def fake_ra(cfg, alias, out, gw, tag):
        out.mkdir(parents=True)
        shutil.copy2(src["repoaudit"] / "dfbscan.log", out / "dfbscan.log")
        m = {"run": tag, "control": "repoaudit", "alias": alias, "provider": "openai", "requested_model": "m",
             "response_models_observed": [], "start": "x", "start_us": db.now_us(), "wall_clock_s": 0,
             "complete": True, "findings": 0, "green": True, "input_tokens": 0, "output_tokens": 0}
        m["output_sha256"] = {"dfbscan.log": s1.sha256_file(out / "dfbscan.log")}
        (out / "manifest.json").write_text(json.dumps(m))
        return m

    def fake_sg(cfg, out, tag):
        shutil.copytree(src["semgrep"], out)
        m = json.loads((out / "manifest.json").read_text())
        m.update(run=tag, start_us=db.now_us())
        return m

    monkeypatch.setattr(s1, "_run_repoaudit", fake_ra)
    monkeypatch.setattr(s1, "_run_semgrep", fake_sg)
    monkeypatch.setattr(s1, "ModelGateway", _FakeGateway)
    monkeypatch.setattr(s1.setup_env, "subject_state", lambda: {"head": "160f5bc", "pinned": True,
                                                                 "tracked_files_modified": False})
    cfg = s1.Stage1Config.from_protocol(protocol.load(), protocol.base_dir())
    models = RunModels()
    models.add("repoaudit", "openai", "development-placeholder", "sk-test-not-a-key")
    c = cycles.create("pilot", None)
    assert s1.run(c, cfg, models, progress=QUIET)
    st = c.data["stages"]["1"]
    assert st["checks"]["decision context written before its first basis run, decision after its last"]
    assert st["outcome"]["decisions"]["count"] == 5 and st["outcome"]["semgrep_runs"] == 1
    out = stage1_dir(c)
    ctx = json.loads((out / "decisions" / "G-pipe-01" / "decision_context.json").read_text())
    assert ctx["basis_runs"][1] == "semgrep/run001" and ctx["control_version"].startswith("repoaudit@160f5bc+semgrep@")
    assert ctx["intent"]["scope_ref"]["sha256"] == s1.sha256_file(DPROTO.parent / "manifests" / "M_h.json")


def _main_only(proto):
    """The fixture protocol narrowed to five RepoAudit decisions plus one standalone Semgrep scan."""
    groups = [{"group": "G-main", "control": "repoaudit", "basis": ["repoaudit"], "policy": "P1@1", "rule": "DR-11",
               "count": 5}]
    return {**proto, "decisions": {**proto["decisions"], "groups": groups},
            "acquisition": {**proto["acquisition"], "semgrep_runs": 1}}


def test_standalone_semgrep_is_retained_but_in_no_decision_basis(root):
    proto = _main_only(protocol.load())
    c = devfixture.import_cycle(FIX, RUNS, semgrep=["semgrep/run001"], decisions=proto, base=protocol.base_dir())
    d, store, q = _corpus(c)
    assert q.decisions() == [f"G-main-0{i}" for i in range(1, 6)]
    assert all(not any(r.startswith("semgrep/") for r in q.decision(x)["binding"]["payload"]["basis_runs"])
               for x in q.decisions())
    assert any(r["run"] == "semgrep/run001" for r in Ledger(d).records())       # ingested, standalone
    with pytest.raises(devfixture.DevFixtureError, match="standalone"):
        devfixture.import_cycle(FIX, RUNS, semgrep=[], decisions=proto, base=protocol.base_dir())


# ---------------------------------------------------------------- ingest, queries, failures
def test_ingest_binds_every_decision_completely(root):
    c = _dev_cycle()
    d, store, q = _corpus(c)
    assert q.decisions() == ["G-main-01", "G-main-02", "G-main-03", "G-pipe-01", "G-strict-01"]
    for did in q.decisions():
        dec = q.decision(did)
        assert dec["status"] == "complete"
        p = dec["binding"]["payload"]
        basis = q.basis(did)["records"]
        assert {r["run"] for r in basis} == set(p["basis_runs"]) and len(basis) == p["basis_count"] > 0
        assert not any(r.get("synthetic") for r in basis)
        txt = q.policy_text(p["policy_record"])
        assert isinstance(txt, bytes) and json.loads(txt)["id"] == dec["policy"]["payload"]["id"]
        n = f"decision:{did}"
        kinds = {e["kind"] for e in store.out_edges(n)}
        assert kinds >= {"for", "under", "by", "verdict"}
        assert (d / "decisions" / f"{did}.dot").exists()
    pipe = q.decision("G-pipe-01")
    assert len(pipe["binding"]["payload"]["basis_runs"]) == 2 and pipe["policy"]["payload"]["id"] == "P2"
    assert q.basis("G-main-01", kinds=["repoaudit.analysis_unit"])["records"]
    assert q.decision("nope")["status"] == "unavailable" and q.policy_text("nope") == "unavailable"


def test_missing_basis_run_fails_without_writing(root, tmp_path):
    c = _dev_cycle()
    s1d = stage1_dir(c)
    plane = EvidencePlane(tmp_path / "plane")
    first = [b for t, b in bundles(s1d) if t != "gpt-pw-m1/run001"]
    for t, b in bundles(s1d):
        if t != "gpt-pw-m1/run001":
            plane.ingest(b, t, {})
    head = plane.ledger.head
    target = next(b for b in db.bundles(s1d) if "gpt-pw-m1/run001" in json.loads((b / "decision_context.json").read_text())["basis_runs"])
    with pytest.raises(DecisionIngestError):
        plane.ingest_decision(target, {})
    assert plane.ledger.head == head and first


def test_partial_and_unavailable_never_complete(root, tmp_path):
    c = _dev_cycle()
    d, store, q = _corpus(c)
    did = "G-main-01"
    basis_id = q.decision(did)["binding"]["payload"]["basis_record_ids"][0]
    binding_id = q.decision(did)["binding"]["id"]
    for drop, want in ((basis_id, "partial"), (binding_id, "unavailable")):
        copy = tmp_path / f"copy-{want}"
        shutil.copytree(d, copy)
        lines = [l for l in (copy / "ledger.jsonl").read_text().splitlines() if json.loads(l)["id"] != drop]
        (copy / "ledger.jsonl").write_text("\n".join(lines) + "\n")
        assert QueryAPI(store, Ledger(copy)).decision(did)["status"] == want
        assert Ledger(copy).verify()                                                # the chain also shows it


def test_synthetic_decision_is_marked(root, tmp_path):
    from pwexp.stages.stage3_scale import synthetic_bundle
    c = _dev_cycle()
    s1d = stage1_dir(c)
    tag, b = bundles(s1d)[0]
    plane = EvidencePlane(tmp_path / "scale")
    syn = synthetic_bundle(b, tmp_path / "syn", "s1")
    plane.ingest(syn, "synthetic/run001", {"synthetic": True})
    bundle = tmp_path / "dsyn"
    db.write_context(bundle, "S-01", "repoaudit", "v", INTENT, "P1", 1, b"{}", ["synthetic/run001"], "DR-11")
    db.write_decision(bundle, {"synthetic/run001": True}, "h")
    plane.ingest_decision(bundle, {}, synthetic=True)
    rec = plane.query.decision("S-01")
    assert rec["status"] == "complete" and rec["binding"].get("synthetic") is True
    assert all(r.get("synthetic") for r in plane.query.basis("S-01")["records"])
    export_decision(plane.store, tmp_path / "s.dot", "S-01")


def test_cli_records_root_and_protocol(root, tmp_path, capsys, monkeypatch):
    from pwexp.cli import main
    monkeypatch.setenv("PWEXP_RECORDS_ROOT", "")   # main() sets these; registering them restores them afterwards
    rr = tmp_path / "elsewhere"
    assert main(["--records-root", str(rr), "--protocol", str(DPROTO), "import-dev"]) == 0
    assert (rr / "cycles" / "pilot-0001" / "stage1" / "attempt1" / "decisions" / "G-main-01").is_dir()
    assert main(["run-stage", "2", "--cycle", "pilot-0001", "--records-root", str(rr)]) == 0
    assert "G-pipe-01 complete" in capsys.readouterr().out


def test_model_check_reports_without_the_key(monkeypatch):
    from pwexp import gateway
    from pwexp.models import RunModels
    m = RunModels()
    e = m.add("repoaudit", "openai", "gpt-test", "sk-secret-value-123")
    monkeypatch.setattr(gateway.ModelGateway, "_post", staticmethod(lambda url, h, b: (200, {"model": "gpt-test-x"})))
    ok, detail = gateway.check_model(e)
    assert ok and "gpt-test" in detail and "sk-secret" not in detail
    monkeypatch.setattr(gateway.ModelGateway, "_post", staticmethod(
        lambda url, h, b: (401, {"error": {"message": "bad key sk-secret-value-123"}})))
    ok, detail = gateway.check_model(e)
    assert not ok and "401" in detail and "sk-secret-value-123" not in detail


def test_keys_from_stdin(monkeypatch):
    import io
    from pwexp.cli import _stage1_models
    monkeypatch.setattr("sys.stdin", io.StringIO("sk-one-xxxxxxxx\nsk-two-xxxxxxxx\n"))
    m = _stage1_models(["openai:a", "anthropic:b"], "", key_stdin=True)
    assert [e.model for e in m.entries()] == ["a", "b"] and m.entries()[1].key == "sk-two-xxxxxxxx"
    m.clear()


def test_standalone_semgrep_scan_in_a_decision_schedule(root, monkeypatch):
    from pwexp import cycles
    from pwexp.models import RunModels
    calls = []
    monkeypatch.setattr(s1, "_run_repoaudit", lambda cfg, alias, out, gw, tag: (out.mkdir(parents=True), calls.append(tag),
        {"run": tag, "control": "repoaudit", "alias": alias, "start_us": db.now_us(), "wall_clock_s": 0, "complete": True,
         "findings": 0, "green": True, "input_tokens": 0, "output_tokens": 0, "output_sha256": {}})[2])
    monkeypatch.setattr(s1, "_run_semgrep", lambda cfg, out, tag: (out.mkdir(parents=True), calls.append(tag),
        {"run": tag, "control": "semgrep", "start_us": db.now_us(), "wall_clock_s": 0, "green": True,
         "output_sha256": {}})[2])
    monkeypatch.setattr(s1, "ModelGateway", _FakeGateway)
    monkeypatch.setattr(s1.setup_env, "subject_state", lambda: {"head": "160f5bc", "pinned": True, "tracked_files_modified": False})
    proto = protocol.load()
    proto["decisions"]["groups"] = [{"group": "G-main", "control": "repoaudit", "basis": ["repoaudit"], "policy": "P1@1",
                                     "rule": "DR-11", "count": 2}]
    proto["acquisition"]["semgrep_runs"] = 1
    cfg = s1.Stage1Config.from_protocol(proto, protocol.base_dir())
    models = RunModels()
    models.add("repoaudit", "openai", "development-placeholder", "sk-test-not-a-key")
    c = cycles.create("pilot", None)
    assert s1.run(c, cfg, models, progress=QUIET)
    assert calls[-1] == "semgrep/run001" and sum(t.startswith("gpt-pw") for t in calls) == 2
    plan = json.loads((stage1_dir(c) / "plan.json").read_text())
    assert not any("semgrep/run001" in d.get("basis_runs", []) for d in plan["decisions"])


def test_repoaudit_gets_a_neutral_identical_copy(tmp_path):
    """RepoAudit skips any file whose absolute path contains 'test' or 'example'; the subject copy avoids both."""
    from pwexp.hashing import manifest_hash, tree_manifest
    target = tmp_path / "my-testing-checkout" / "target"
    (target / "pkg").mkdir(parents=True)
    (target / "pkg" / "m.py").write_text("def f():\n    return None\n")
    copy = s1._subject_copy(target)
    try:
        assert copy.name == "target" and not any(w in str(copy).lower() for w in s1.SKIPPED_PATH_WORDS)
        assert manifest_hash(tree_manifest(copy)) == manifest_hash(tree_manifest(target))
    finally:
        shutil.rmtree(copy.parent)


def _pausable_stage1(monkeypatch, count=4, stop_at=None, hangup=False):
    """A decision schedule of `count` RepoAudit decisions plus one standalone Semgrep scan with fake controls;
    the RepoAudit call number `stop_at` is cut off by Ctrl-C after its run folder was created."""
    from pwexp.models import RunModels
    calls = []

    def fake_ra(cfg, alias, out, gw, tag):
        out.mkdir(parents=True)
        calls.append(tag)
        if len(calls) == stop_at:
            if hangup:
                os.kill(os.getpid(), signal.SIGHUP)   # the terminal closed
            raise KeyboardInterrupt
        m = {"run": tag, "control": "repoaudit", "alias": alias, "start_us": db.now_us(), "wall_clock_s": 0,
             "complete": True, "findings": 0, "green": True, "input_tokens": 0, "output_tokens": 0, "output_sha256": {}}
        (out / "manifest.json").write_text(json.dumps(m))
        return m

    def fake_sg(cfg, out, tag):
        out.mkdir(parents=True)
        calls.append(tag)
        m = {"run": tag, "control": "semgrep", "start_us": db.now_us(), "wall_clock_s": 0, "green": True,
             "output_sha256": {}}
        (out / "manifest.json").write_text(json.dumps(m))
        return m

    monkeypatch.setattr(s1, "_run_repoaudit", fake_ra)
    monkeypatch.setattr(s1, "_run_semgrep", fake_sg)
    monkeypatch.setattr(s1, "ModelGateway", _FakeGateway)
    monkeypatch.setattr(s1.setup_env, "subject_state", lambda: {"head": "160f5bc", "pinned": True, "tracked_files_modified": False})
    proto = protocol.load()
    proto["decisions"]["groups"] = [{"group": "G-main", "control": "repoaudit", "basis": ["repoaudit"], "policy": "P1@1",
                                     "rule": "DR-11", "count": count}]
    proto["acquisition"]["semgrep_runs"] = 1
    models = RunModels()
    models.add("repoaudit", "openai", "development-placeholder", "sk-test-not-a-key")
    return s1.Stage1Config.from_protocol(proto, protocol.base_dir()), models, calls


def test_paused_stage1_resumes_keeping_recorded_decisions(root, monkeypatch):
    from pwexp import cycles
    cfg, models, calls = _pausable_stage1(monkeypatch, stop_at=3)
    c = cycles.create("pilot", None)
    with pytest.raises(s1.StagePaused, match="Ctrl-C"):
        s1.run(c, cfg, models, progress=QUIET)
    c = cycles.load(c.id)
    assert c.stage_state(1) == "paused" and not c.can_start(1)[0] and c.can_resume(1)[0]
    assert len(c.data["stages"]["1"]["pauses"]) == 1
    calls.clear()
    assert s1.run(c, cfg, models, progress=QUIET, resume=True)
    assert len([t for t in calls if t.startswith("gpt-pw")]) == 2           # decisions 1-2 kept; 3 rerun, 4 new
    st = c.data["stages"]["1"]
    assert all(st["checks"].values()) and st["outcome"]["decisions"]["count"] == 4
    assert sorted(i["moved"].split("/")[0] for i in st["outcome"]["interrupted"]) == ["decisions", "repoaudit"]
    out = stage1_dir(c)
    assert (out / "interrupted" / "decisions").is_dir() and (out / "interrupted" / "repoaudit").is_dir()
    events = [json.loads(x)["event"] for x in (c.path / "stage-log.jsonl").read_text().splitlines()]
    assert events == ["stage_paused", "stage_resumed", "stage_complete"]


def test_stopped_stage1_resumes_and_completes_a_decision_whose_runs_finished(root, monkeypatch):
    """A kill or reboot leaves the stage 'running' with no process; a decision whose basis runs all finished is
    completed from them rather than paid for again."""
    from pwexp import cycles
    cfg, models, calls = _pausable_stage1(monkeypatch, stop_at=3)
    c = cycles.create("pilot", None)
    with pytest.raises(s1.StagePaused):
        s1.run(c, cfg, models, progress=QUIET)
    c = cycles.load(c.id)
    c.data["stages"]["1"]["status"] = "running"        # as if killed: no pause was recorded
    c.save()
    out = c.path / "stage1" / "attempt1"
    done = [b for b in (out / "decisions").iterdir() if (b / "decision.json").exists()]
    for f in ("decision.json", "manifest.json"):
        (done[0] / f).unlink()                            # its run finished, the decision was not yet written
    calls.clear()
    assert s1.run(c, cfg, models, progress=QUIET, resume=True)
    assert len([t for t in calls if t.startswith("gpt-pw")]) == 2
    assert c.data["stages"]["1"]["resumed"][0]["from"] == "stopped without pausing"
    assert all(c.data["stages"]["1"]["checks"].values())


def test_resume_refused_when_the_plan_changed(root, monkeypatch):
    from pwexp import cycles
    cfg, models, _ = _pausable_stage1(monkeypatch, stop_at=2)
    c = cycles.create("pilot", None)
    with pytest.raises(s1.StagePaused):
        s1.run(c, cfg, models, progress=QUIET)
    cfg.seed += 1
    with pytest.raises(ValueError, match="seed changed"):
        s1.run(cycles.load(c.id), cfg, models, progress=QUIET, resume=True)
    assert cycles.load(c.id).stage_state(1) == "paused"


def test_closed_terminal_pauses_stage1(root, monkeypatch):
    from pwexp import cycles
    cfg, models, _ = _pausable_stage1(monkeypatch, stop_at=2, hangup=True)
    c = cycles.create("pilot", None)
    with pytest.raises(s1.StagePaused, match="SIGHUP"):
        s1.run(c, cfg, models, progress=QUIET)
    assert cycles.load(c.id).data["stages"]["1"]["pauses"][0]["reason"] == "SIGHUP"
    assert signal.getsignal(signal.SIGHUP) is not s1._stop


def test_stage2_left_running_by_a_dead_process_reruns_as_a_new_attempt(root):
    c = _dev_cycle()
    c.data["stages"]["2"]["status"] = "running"          # as if the process was killed mid-stage
    c.save()
    (c.path / "stage2" / "attempt1").mkdir(parents=True)
    assert c.can_start(2)[0]
    assert s2.run(c, repetitions=1, progress=QUIET)
    st = c.data["stages"]["2"]
    assert st["attempt"] == 2 and st["stopped_attempts"] == [1] and (c.path / "stage2" / "attempt1").is_dir()
    events = [json.loads(x)["event"] for x in (c.path / "stage-log.jsonl").read_text().splitlines()]
    assert events[-2:] == ["stage_stopped", "stage_complete"]
