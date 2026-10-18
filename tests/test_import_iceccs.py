"""Importer for the first study's public RepoAudit runs (fixtures only)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from pwexp import cycles
from pwexp.hashing import sha256_file
from pwexp.importers import iceccs

FIX = Path(__file__).parent / "fixtures" / "iceccs-live-v1" / "python_npd"
RUNS = ["gpt-4.1/run01", "gpt-4.1/run15", "gpt-4.1/run25", "gpt-4.1/run28", "gpt-4o-mini/run01"]


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("PWEXP_ROOT", str(tmp_path))
    (tmp_path / "records" / "published").mkdir(parents=True)
    return tmp_path


def test_fixtures_match_their_source_checksums():
    for r in RUNS:
        checks = json.loads((FIX / r / "checksums.json").read_text())
        for name, h in checks.items():
            assert sha256_file(FIX / r / name) == h, f"{r}/{name}"


def test_import_cycle_is_a_marked_pilot(root):
    c = cycles.load(iceccs.import_cycle(FIX, RUNS).id)
    assert c.data["mode"] == "pilot" and c.data["imported_from"]["commit"] == iceccs.SOURCE_COMMIT
    assert "not a result" in c.data["imported_from"]["purpose"]
    assert c.stage_state(1) == "complete" and c.next_stage() == 2 and c.log.verify() == []
    out = c.data["stages"]["1"]["outcome"]
    assert out["repoaudit_runs"] == 5 and out["repoaudit_green"] == 0  # every source run reports planted bugs


def test_native_files_byte_identical_and_wrappers_converted(root):
    c = iceccs.import_cycle(FIX, RUNS)
    run = c.path / "stage1" / "attempt1" / "repoaudit" / "gpt-pw-m1" / "run003"   # gpt-4.1/run25
    for name in iceccs.NATIVE:
        assert sha256_file(run / name) == sha256_file(FIX / "gpt-4.1/run25" / name)
    man = json.loads((run / "manifest.json").read_text())
    assert man["imported_from"]["path"].endswith("gpt-4.1/run25") and man["findings"] == 4 and not man["green"]
    calls = [json.loads(l) for l in (run / "calls.jsonl").read_text().splitlines()]
    assert calls and all(c["run"] == "gpt-pw-m1/run003" and c["provider"] == "openai" for c in calls)
    assert (c.path / "stage1" / "attempt1" / "repoaudit" / "gpt-pw-m2" / "run001").exists()  # gpt-4o-mini


def test_tampered_source_is_rejected(root, tmp_path):
    bad = tmp_path / "bad" / "gpt-4.1" / "run01"
    shutil.copytree(FIX / "gpt-4.1/run01", bad)
    with (bad / "dfbscan.log").open("a") as f:
        f.write("tampered\n")
    with pytest.raises(iceccs.ImportError_):
        iceccs.import_cycle(tmp_path / "bad", ["gpt-4.1/run01"])
