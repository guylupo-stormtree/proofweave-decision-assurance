"""P0 foundation tests: hashing, hash-chained logs, protocol lock, cycles and gating, key handling."""
from __future__ import annotations

import json
import pickle
from pathlib import Path

import pytest
import yaml

from pwexp import chain, cycles, hashing, models, protocol


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("PWEXP_ROOT", str(tmp_path))
    (tmp_path / "protocol").mkdir()
    (tmp_path / "records" / "published").mkdir(parents=True)
    return tmp_path


def _complete_protocol(root: Path) -> Path:
    (root / "targets" / "demo").mkdir(parents=True)
    (root / "targets" / "demo" / "a.py").write_text("def f():\n    return None\n")
    (root / "protocol" / "required-set.json").write_text('{"items": []}\n')
    (root / "protocol" / "required-set-review.md").write_text("reviewed\n")
    proto = yaml.safe_load((Path(__file__).parents[1] / "protocol" / "protocol.yaml").read_text())
    proto["target"].update(repository="https://example.org/demo", commit="abc123", snapshot_path="targets/demo")
    proto["divergence"]["tau"] = 0.8
    proto["acquisition"].update(repoaudit_runs_per_model=10, semgrep_runs=3,
                                models=[{"provider": "openai", "model": "gpt-4.1"}])
    proto["semgrep"].update(version="1.0.0", ruleset="p/python")
    proto["timing"]["repetitions"] = 5
    p = root / "protocol" / "protocol.yaml"
    p.write_text(yaml.safe_dump(proto))
    return p


# ------------------------------------------------------------------ hashing
def test_canonical_json_is_order_independent():
    assert hashing.canonical_json({"b": 1, "a": [1, 2]}) == hashing.canonical_json({"a": [1, 2], "b": 1})


def test_tree_manifest_detects_change(tmp_path):
    (tmp_path / "x.txt").write_text("1")
    m1 = hashing.manifest_hash(hashing.tree_manifest(tmp_path))
    (tmp_path / "x.txt").write_text("2")
    assert hashing.manifest_hash(hashing.tree_manifest(tmp_path)) != m1


# ------------------------------------------------------------------ chain
def test_chain_append_and_verify(tmp_path):
    log = chain.HashChainLog(tmp_path / "log.jsonl")
    for i in range(3):
        log.append({"event": "e", "i": i})
    assert log.verify() == []
    assert log.head()[0] == 2


def test_chain_detects_tampering(tmp_path):
    log = chain.HashChainLog(tmp_path / "log.jsonl")
    for i in range(3):
        log.append({"event": "e", "i": i})
    lines = (tmp_path / "log.jsonl").read_text().splitlines()
    rec = json.loads(lines[1])
    rec["i"] = 99
    lines[1] = json.dumps(rec, sort_keys=True)
    (tmp_path / "log.jsonl").write_text("\n".join(lines) + "\n")
    assert any("altered" in p for p in log.verify())


def test_chain_detects_deletion(tmp_path):
    log = chain.HashChainLog(tmp_path / "log.jsonl")
    for i in range(3):
        log.append({"event": "e", "i": i})
    lines = (tmp_path / "log.jsonl").read_text().splitlines()
    (tmp_path / "log.jsonl").write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert log.verify()


# ------------------------------------------------------------------ protocol
def test_template_protocol_is_not_lockable(root):
    (root / "protocol" / "protocol.yaml").write_text(
        (Path(__file__).parents[1] / "protocol" / "protocol.yaml").read_text())
    errs = protocol.problems(protocol.load())
    assert any(e.startswith("divergence.tau") for e in errs)
    with pytest.raises(protocol.ProtocolError):
        protocol.lock()


def test_lock_and_check(root):
    _complete_protocol(root)
    assert protocol.problems(protocol.load()) == []
    doc = protocol.lock()
    ok, info = protocol.check_lock()
    assert ok and info == doc["lock_sha256"]


def test_lock_invalidated_by_change(root):
    p = _complete_protocol(root)
    protocol.lock()
    p.write_text(p.read_text().replace("tau: 0.8", "tau: 0.7"))
    ok, why = protocol.check_lock()
    assert not ok and "changed" in why


def test_keys_rejected_in_protocol(root):
    p = _complete_protocol(root)
    d = yaml.safe_load(p.read_text())
    d["acquisition"]["models"][0]["key"] = "sk-secret"
    p.write_text(yaml.safe_dump(d))
    assert any("keys must never" in e for e in protocol.problems(protocol.load()))


def test_tau_bounds(root):
    p = _complete_protocol(root)
    d = yaml.safe_load(p.read_text())
    d["divergence"]["tau"] = 1.5
    p.write_text(yaml.safe_dump(d))
    assert any("0 < tau < 1" in e for e in protocol.problems(protocol.load()))


# ------------------------------------------------------------------ cycles
def test_cycle_gating_and_log(root):
    c = cycles.create("pilot", None)
    assert c.id == "pilot-0001" and c.next_stage() == 1
    assert not c.can_start(2)[0]
    c.start(1)
    assert c.finish(1, {"accounted": True}, "h1", {"runs": 1})
    assert c.next_stage() == 2 and c.can_start(2)[0]
    assert c.log.verify() == []
    assert cycles.create("pilot", None).id == "pilot-0002"


def test_failed_check_stops_and_reattempts(root):
    c = cycles.create("pilot", None)
    c.start(1)
    assert not c.finish(1, {"accounted": False}, "h", {})
    assert c.data["status"] == "failed" and not c.can_start(2)[0]
    assert c.start(1) == 2  # new attempt; failed attempt stays in the log
    events = [r["event"] for r in c.log.records()]
    assert events == ["stage_failed"]


def test_campaign_requires_lock(root):
    with pytest.raises(cycles.CycleError):
        cycles.create("campaign", None)


def test_replay_starts_at_stage2(root):
    c = cycles.create("replay", None, replay_of="campaign-0001")
    assert c.next_stage() == 2 and c.data["stages"]["1"]["source"] == "published:campaign-0001"


def test_cycle_complete_after_four_stages(root):
    c = cycles.create("pilot", None)
    for n in range(1, 5):
        c.start(n)
        c.finish(n, {"ok": True}, f"h{n}", {})
    assert c.data["status"] == "complete" and c.next_stage() is None


# ------------------------------------------------------------------ models / keys
def test_keys_never_leak():
    rm = models.RunModels()
    e = rm.add("repoaudit", "anthropic", "claude-x", "sk-SECRET")
    assert "sk-SECRET" not in repr(e) and "sk-SECRET" not in json.dumps(rm.public())
    with pytest.raises(TypeError):
        pickle.dumps(e)


def test_aliases_route_through_gateway():
    rm = models.RunModels()
    a = rm.add("repoaudit", "openai", "gpt-4.1", "k1")
    b = rm.add("repoaudit", "anthropic", "claude-x", "k2")
    assert a.alias == "gpt-pw-m1" and b.alias == "gpt-pw-m2" and "gpt" in b.alias
    assert rm.by_alias("gpt-pw-m2").model == "claude-x"


def test_every_entry_needs_a_key_and_one_qa_model():
    rm = models.RunModels()
    with pytest.raises(models.ModelEntryError):
        rm.add("repoaudit", "openai", "gpt-4.1", "")
    rm.add("graph_qa", "anthropic", "claude-x", "k")
    with pytest.raises(models.ModelEntryError):
        rm.add("graph_qa", "openai", "gpt-4.1", "k")


def test_campaign_model_rule():
    rm = models.RunModels()
    rm.add("repoaudit", "openai", "gpt-4.1", "k")
    assert rm.matches_protocol([{"provider": "openai", "model": "gpt-4.1"}])
    rm.add("repoaudit", "anthropic", "claude-x", "k")
    assert not rm.matches_protocol([{"provider": "openai", "model": "gpt-4.1"}])


# ------------------------------------------------------------------ Stage 1 GREEN mapping (DR-11)
def test_green_mapping():
    from pwexp.stages.stage1_acquire import green_repoaudit, green_semgrep
    assert green_repoaudit(True, 0)
    assert not green_repoaudit(True, 2)          # adverse: findings reported
    assert not green_repoaudit(False, 0)         # incomplete is never GREEN
    assert not green_repoaudit(True, None)       # no native report and no log confirmation
    assert green_semgrep(0, 0, 0)
    assert not green_semgrep(0, 1, 0) and not green_semgrep(0, 0, 1) and not green_semgrep(None, 0, 0)
