"""Reporting (DR-01, DR-21): results page, worked-example exhibit, model-vs-model contrast, publication guard."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pwexp.importers import devfixture, iceccs
from pwexp.report import exhibit, publish, results
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
    (tmp_path / "targets").mkdir()
    (tmp_path / "targets" / "fixture-guarded-users").symlink_to(Path(__file__).parents[1] / "targets" / "fixture-guarded-users")
    if TOY.is_dir():
        (tmp_path / "vendor" / "RepoAudit" / "benchmark" / "Python").mkdir(parents=True)
        (tmp_path / "vendor" / "RepoAudit" / "benchmark" / "Python" / "toy").symlink_to(TOY)
    return tmp_path


def _complete(c, required):
    assert s2.run(c, repetitions=1, progress=QUIET)
    assert s3.run(c, repetitions=1, volumes=[10], progress=QUIET)
    assert s4.run(c, required_path=required, progress=QUIET)
    return c


def test_exhibit_shows_three_greens_and_a_real_contrast(root):
    c = _complete(devfixture.import_cycle(DEV, RUNS, semgrep=["semgrep/run001"]), DEV / "required-set.json")
    ex = exhibit.build(c)
    case = ex["case"]
    # the declared pair complements each other: together they cover every flow, neither does alone
    assert case["view"] == "P5" and case["verdict_only"] == "PROCEED" and case["gateway"] == "PROCEED"
    assert len(case["runs"]) == 3 and all(r["green"] for r in case["runs"]) and case["oracle_agrees"]
    con = ex["contrast"]
    assert con and con["kind"] == "V"
    assert {con["covering_run"], con["missing_run"]} <= {r["run"] for r in case["runs"]}
    x = con["excerpt"]
    assert x and x["ledger_record"] and "bytes" in x["location"] and x["text"].strip()
    assert x["event_type"] == "repoaudit.analysis_unit" and "def " in x["text"]   # the receiving function's step
    assert "/home/" not in x["text"] and "/Users/" not in x["text"]       # privacy-treated
    n = ex["narrative"]
    assert {g["term"] for g in ex["glossary"]} >= {"RepoAudit run", "Model (model slot)", "GREEN", "Flow"}
    assert [r["run"] for r in n["runs"]] == ex["columns"] and all(r["text"] and r["role"] for r in n["runs"])
    assert "same model and settings" in con["story"]
    row = next(m for m in ex["matrix"] if m["id"] == con["item"])
    assert row["cells"][con["covering_run"]] > 0 and row["cells"][con["missing_run"]] == 0


def test_pathways_diverge_between_green_runs(root):
    """DR-22: same code, same bug type, same model and settings, all GREEN, different pathways."""
    c = _complete(devfixture.import_cycle(DEV, RUNS, semgrep=["semgrep/run001"]), DEV / "required-set.json")
    pw = exhibit.build(c)["pathways"]
    cells = {(r["from"].split("::")[-1], r["to"].split("::")[-1]): r["cells"] for r in pw["rows"]}
    assert cells[("find_user", "display_name")]["gpt-pw-m1/run001"] and not cells[("find_user", "display_name")]["gpt-pw-m1/run003"]
    assert cells[("resolve_manager", "escalation_chain")]["gpt-pw-m1/run003"] \
        and not cells[("resolve_manager", "escalation_chain")]["gpt-pw-m1/run001"]
    assert any(r["via"] == "argument" for r in pw["rows"])                # None passed as an argument is followed too
    same = [p for p in pw["pairs"] if p["relation"] == "same model, same settings" and p["both_green"]]
    assert same and min(p["similarity"] for p in same) < 0.5
    assert "share only" in pw["summary"]


def test_single_green_run_with_semgrep_holds(root):
    """Two GREENs that leave flows unexamined: verdict-only PROCEED, TAIP HOLD, explained in words."""
    c = _complete(devfixture.import_cycle(DEV, RUNS, semgrep=["semgrep/run001"]), DEV / "required-set.json")
    ex = exhibit.build(c, runs=["gpt-pw-m1/run003", "semgrep/run001"])
    case = ex["case"]
    assert case["verdict_only"] == "PROCEED" and case["taip"] == "INCONCLUSIVE" and case["gateway"] == "HOLD"
    assert case["oracle_agrees"] and {"R09", "R10", "R11"} <= set(case["missing"])
    m = {x["id"]: x["explanation"] for x in ex["narrative"]["missing"]}
    assert "never followed it into display_name()" in m["R09"]
    assert ex["contrast"]["missing_run"] == "gpt-pw-m1/run003"


def test_results_write_produces_presentable_outputs(root):
    c = _complete(devfixture.import_cycle(DEV, RUNS, semgrep=["semgrep/run001"]), DEV / "required-set.json")
    out = results.write(c)
    for f in ("results.json", "exhibit.json", "EXHIBIT.html", "RESULTS.md", "timing.csv", "assurance.csv",
              "report-manifest.json"):
        assert (out / f).is_file(), f
    assert any((out / "paper").glob("*.tex"))
    html = (out / "EXHIBIT.html").read_text()
    md = (out / "RESULTS.md").read_text()
    con = json.loads((out / "exhibit.json").read_text())["contrast"]
    assert con["item"] in html and con["item"] in md and "PROCEED" in html
    assert "<details class=\"gl\">" in html and "Glossary" in md                    # collapsible glossary on top
    assert html.index("Glossary") < html.index("In short") < html.index("different pathways") \
        < html.index("Each run, in plain words") < html.index("What each run actually examined")
    assert "different pathways" in md
    for m in json.loads((out / "results.json").read_text())["macros"].values():
        assert "source" in m                                              # every number traceable


def test_operator_chosen_item_and_runs(root):
    c = _complete(devfixture.import_cycle(DEV, RUNS, semgrep=["semgrep/run001"]), DEV / "required-set.json")
    default = exhibit.build(c)
    other = next(m["id"] for m in default["matrix"] if m["id"] != default["contrast"]["item"])
    ex = exhibit.build(c, item_id=other, runs=default["columns"][:2])
    assert ex["contrast"]["item"] == other and [r["run"] for r in ex["case"]["runs"]] == default["columns"][:2]
    # a presenter's selection is decided afresh, never shown with P5's decision
    assert ex["case"]["view"] == "presenter's choice" and ex["case"]["oracle_agrees"]
    assert "R15" in ex["case"]["missing"]                                   # two RepoAudit runs: no Semgrep scan


@pytest.mark.skipif(not TOY.is_dir(), reason="RepoAudit submodule not initialised")
def test_model_versus_model_on_first_study_runs(root, tmp_path):
    fix = Path(__file__).parent / "fixtures" / "iceccs-live-v1" / "python_npd"
    r = draft(TOY)
    r["items"].append({"id": "R99", "kind": "V", "functions": ["NPD/case04.py::test4_test", "NPD/case04.py::test4_inner_call"],
                       "rationale": "case04 inter-procedural flow (reviewer-added)"})
    req = tmp_path / "toy.json"
    req.write_text(json.dumps(r))
    c = _complete(iceccs.import_cycle(fix, ["gpt-4.1/run25", "gpt-4o-mini/run01"]), req)
    ex = exhibit.build(c)
    models = {r: i["model"] for r, i in ex["run_info"].items()}
    assert len(set(models.values())) == 2                                  # two different models side by side
    con = ex["contrast"]
    assert con and con["item"] == "R99" and con["kind"] == "V"
    assert models[con["covering_run"]] == "gpt-4.1" and models[con["missing_run"]] == "gpt-4o-mini"       # one model saw it, the other did not
    assert con["excerpt"]["text"].strip() and "Two different models" in con["story"]
    # the presenter may also fix the comparison explicitly
    pair = exhibit.build(c, item_id=con["item"], runs=[con["missing_run"]])
    assert pair["contrast"]["missing_run"] == con["missing_run"] and pair["contrast"]["covering_run"] == con["covering_run"]


def test_publish_guards_and_preview(root):
    c = _complete(devfixture.import_cycle(DEV, RUNS, semgrep=["semgrep/run001"]), DEV / "required-set.json")
    with pytest.raises(publish.PublishError, match="campaign"):
        publish.publish(c.id, "test", "tester")
    dest = publish.publish(c.id, "test", "tester", preview=True)
    assert (dest / "results.json").is_file() and (dest / "report" / "EXHIBIT.html").is_file()
    assert not any((root / "records" / "published").iterdir())
    assert not (root / "records" / "publications.jsonl").exists()
