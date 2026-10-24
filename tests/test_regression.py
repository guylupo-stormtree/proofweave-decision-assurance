"""PW-REG-1: with decision binding present but unused, the fixtures' corpus identity equals pw-v0.1.0."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import regression  # noqa: E402

TOY = Path(__file__).parents[1] / "vendor" / "RepoAudit" / "benchmark" / "Python" / "toy"
EXPECTED = json.loads((Path(__file__).parent / "fixtures" / "regression-pw-v0.1.0.json").read_text())


@pytest.mark.skipif(not TOY.is_dir(), reason="RepoAudit submodule not initialised")
def test_corpus_identity_unchanged_since_pw_v0_1_0(tmp_path, monkeypatch):
    monkeypatch.setenv("PWEXP_ROOT", str(tmp_path))
    (tmp_path / "records" / "published").mkdir(parents=True)
    (tmp_path / "targets").mkdir()
    (tmp_path / "targets" / "fixture-guarded-users").symlink_to(Path(__file__).parents[1] / "targets" / "fixture-guarded-users")
    (tmp_path / "vendor" / "RepoAudit" / "benchmark" / "Python").mkdir(parents=True)
    (tmp_path / "vendor" / "RepoAudit" / "benchmark" / "Python" / "toy").symlink_to(TOY)
    got = regression.build_all()
    for name, ident in got.items():
        assert ident == EXPECTED[name], name
