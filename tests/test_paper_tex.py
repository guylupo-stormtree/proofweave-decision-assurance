"""Paper LaTeX generation: pending defaults, traceability, pilot watermark, campaign guard, determinism."""
from __future__ import annotations

import json

import pytest

from pwexp.report import paper_tex as pt


def test_pending_without_inputs(tmp_path):
    files = pt.build(None, None)
    assert set(files) == {"protocol-macros.tex", "results-macros.tex", "tab-timing-body.tex", "tab-assurance-body.tex"}
    assert r"\renewcommand{\PWRunTotal}{\pending}" in files["results-macros.tex"]
    assert "PWResultStatus" not in files["results-macros.tex"]  # author placeholder kept
    assert "$1{,}000$ & \\pending" in files["tab-timing-body.tex"]
    assert files["tab-assurance-body.tex"].count(r"\\") == 11


def test_values_need_a_source(tmp_path):
    r = tmp_path / "results.json"
    r.write_text(json.dumps({"mode": "pilot", "macros": {"PWRunTotal": {"value": "12"}}}))
    with pytest.raises(pt.PaperTexError):
        pt.build(None, r)


def test_pilot_watermark_and_values(tmp_path):
    r = tmp_path / "results.json"
    r.write_text(json.dumps({"mode": "pilot", "cycle": "pilot-0001",
                             "macros": {"PWRunTotal": {"value": "12", "source": "x"},
                                        "PWResultStatus": {"value": "Status.", "source": "x"}},
                             "timing_rows": {"10": {"median": "3 ms"}}}))
    f = pt.build(None, r)
    assert r"\renewcommand{\PWRunTotal}{12}" in f["results-macros.tex"]
    assert "PILOT DATA, NOT CAMPAIGN RESULTS." in f["results-macros.tex"]
    assert "% source cycle: pilot-0001" in f["results-macros.tex"] and "3 ms" in f["tab-timing-body.tex"]


def test_campaign_requires_freeze_hash(tmp_path):
    r = tmp_path / "results.json"
    r.write_text(json.dumps({"mode": "campaign", "macros": {}}))
    with pytest.raises(pt.PaperTexError):
        pt.build(None, r)


def test_regeneration_is_stable(tmp_path):
    pt.write(tmp_path, pt.build(None, None))
    assert pt.stale(tmp_path, pt.build(None, None)) == []
