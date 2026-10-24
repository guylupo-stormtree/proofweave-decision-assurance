"""Worked-example exhibit (DR-21): what "three GREENs, not enough coverage" looks like in a real cycle.

Built only from the cycle's sealed corpus E and Stage 4 decisions:
  case      the Three-GREENs view (P5): each run's verdict, model and settings; verdict-only action vs TAIP
  matrix    required items × runs: how many admissible witnesses each run left for each item
  contrast  one requirement covered by some run but missing from a P5 run, with the exact RepoAudit log
            excerpt (native bytes referenced by the ledger) for the covering run, and what the other run did
            examine. Selection rule: the first required item, in R's order, that some run covers and some P5
            run does not; the operator may choose another item or other runs.
Illustrative only: it explains the reported results and never replaces them. Excerpts are privacy-treated.
"""
from __future__ import annotations

import json
import re

import oracle
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..cycles import Cycle
from ..paths import repo_root
from ..proofweave.graph import InMemoryGraphStore
from ..proofweave.ledger import Ledger
from ..proofweave.query import QueryAPI
from ..stages.common import bundles, stage1_dir, target_root
from ..taip import requirements
from ..taip.evaluate import Evaluator, View, verdict_only

KIND_EVENT = {"A": ("repoaudit.analysis_unit",),
              "V": ("repoaudit.analysis_unit", "repoaudit.validation_request"), "S": ("semgrep.scan",)}
KIND_TEXT = {"A": "analysed", "V": "followed the flow", "S": "scanned with the pinned rules"}

GLOSSARY = [
    ("RepoAudit run", "One complete execution of RepoAudit, an AI code auditor, on the target code: here its null-pointer "
     "detector (dfbscan), unmodified, in a fresh process. A run ID such as gpt-pw-m1/run002 means model slot m1, second run."),
    ("Model (model slot)", "The AI model RepoAudit asked its questions to. The harness labels each configured model gpt-pw-m1, "
     "gpt-pw-m2, … (RepoAudit only accepts names containing \"gpt\"); each card shows the real model behind the label and "
     "its temperature. Two slots can be two different models, or one model at two temperatures."),
    ("Temperature", "How much randomness the model uses when it answers. 0 is the most repeatable; higher values let the "
     "same model give different answers to the same question."),
    ("Semgrep run", "One execution of Semgrep, a conventional pattern scanner (no AI), with a fixed rule file. It checks "
     "code patterns file by file; it does not follow values from one function into another."),
    ("GREEN", "The run finished normally (exit code 0, no crash, its own log present, not timed out) and reported zero "
     "bugs. GREEN says what the tool found in what it looked at. It does not say how much of the code it looked at."),
    ("Flow", "A path a value can take through the code. Here: a function can return None, and another function uses that "
     "result. If the user does not check for None, the program can crash (a null-pointer dereference). RepoAudit finds "
     "such paths and asks the model, through its path validator, whether the None can really reach a use. On this page "
     "a flow counts as validated when RepoAudit's own log shows that question was asked, whatever the answer."),
    ("Analysis unit", "RepoAudit asking the model about one function as a place where None can originate (a source)."),
    ("Required set (R01, R02, …)", "The list of things that must have been examined before a GREEN can be trusted. It is "
     "derived from the code independently of RepoAudit and reviewed by a person. Kinds: A = function analysed as a None "
     "source; V = flow validated; S = file scanned by Semgrep's fixed rules."),
    ("Witness", "A ledger record that shows a requirement was covered. It points to the exact bytes of the tool's own log, "
     "so anyone can open the log and check it."),
    ("Evidence view", "The set of runs the gateway is asked to decide on. P5 is the natural three-GREENs view: two GREEN "
     "RepoAudit runs plus one GREEN Semgrep run."),
    ("Divergent pair", "The two RepoAudit runs in P5: the first pair, in run order, of GREEN runs from the same model slot "
     "whose examined evidence overlaps less than the threshold τ (Jaccard similarity). Same tool, same model, same code, "
     "yet different coverage."),
    ("Verdict-only gateway", "A gateway that trusts verdicts: PROCEED when every run is GREEN, otherwise HOLD."),
    ("ProofWeave + TAIP", "ProofWeave records every run's native output in a tamper-evident ledger and links it into a "
     "graph. TAIP then checks each requirement against that evidence: PASS (all covered, no accepted finding), "
     "INCONCLUSIVE (something not covered) or FAIL (an accepted finding on a required item). The gateway PROCEEDs only on "
     "PASS; otherwise it HOLDs."),
    ("Independent oracle", "Separate code, sharing nothing with ProofWeave, that computes the expected decision straight "
     "from the raw logs. It checks that ProofWeave decided correctly."),
]


@dataclass
class Corpus:
    store: InMemoryGraphStore
    ledger: Ledger
    records: dict[str, dict[str, Any]]
    query: QueryAPI


def open_corpus(cycle: Cycle) -> Corpus:
    d = cycle.path / "stage2" / cycle.data["stages"]["2"]["outcome"]["attempt_dir"] / "corpus"
    store = InMemoryGraphStore.load(d / "graph-checkpoint.json")
    ledger = Ledger(d)
    return Corpus(store, ledger, {r["record_hash"]: r for r in ledger.records()}, QueryAPI(store))


def _req(item: dict) -> dict:
    return {"kind": item["kind"], **{k: item[k] for k in ("function", "functions", "file") if k in item}}


def describe(item: dict) -> str:
    if item["kind"] == "A":
        return f"{item['function']} analysed (its None source)"
    if item["kind"] == "V":
        return "flow " + " → ".join(item["functions"]) + " followed"
    return f"{item['file']} scanned by the fixed rules"


def _fn(name: str) -> str:
    return name.split("::")[-1] + "()"


def plain(item: dict) -> str:
    """The requirement in words."""
    if item["kind"] == "A":
        return f"RepoAudit examined {_fn(item['function'])} as a place where None can originate"
    if item["kind"] == "V":
        f = item["functions"]
        via = f" via {', '.join(_fn(x) for x in f[1:-1])}" if len(f) > 2 else ""
        return f"RepoAudit followed a None from {_fn(f[0])} into {_fn(f[-1])}{via}"
    return f"Semgrep scanned {item['file']} with the fixed rules"


def _model(r: dict) -> str:
    if r["control"] == "Semgrep":
        return "Semgrep, fixed rules, no AI model"
    t = f", temperature {r['temperature']}" if r["temperature"] is not None else ""
    return f"{r['model'] or 'unknown model'}{t}"


def _n(k: int, one: str, many: str | None = None) -> str:
    return f"{k} {one if k == 1 else (many or one + 's')}"


def _ids(xs: list[str]) -> str:
    return ", ".join(xs) if xs else "none"


def _narrative(items: list[dict], matrix: list[dict], info: dict, case_runs: list[str], columns: list[str],
               case: dict, pair: dict, chosen_by_operator: bool) -> dict[str, Any]:
    by_id = {m["id"]: m for m in matrix}
    a_of = {i["function"]: i["id"] for i in items if i["kind"] == "A"}
    kinds = {k: [i for i in items if i["kind"] == k] for k in "AVS"}
    case_ra = [r for r in case_runs if info.get(r, {}).get("control") == "RepoAudit"]
    covered_case = [m["id"] for m in matrix if m["in_case"]]
    n_green = sum(1 for r in case_runs if info.get(r, {}).get("green"))

    summary = (f"{n_green} of the {len(case_runs)} runs in this view reported GREEN: no bugs found. A gateway that trusts "
               f"verdicts would {case['verdict_only']}. ProofWeave checked what each run actually examined against the "
               f"required set: {len(covered_case)} of {len(items)} requirements are covered by these runs and "
               + (f"{len(case['missing'])} are not ({_ids(case['missing'])}). " if case["missing"] else "none is missing. ") +
               f"TAIP therefore rates the evidence "
               f"{case['taip']} and the gateway decides {case['gateway']}. The independent oracle "
               f"{'reaches the same decision' if case['oracle_agrees'] else 'DISAGREES'}.")
    if not case_runs:
        summary = (f"This cycle has no three-GREENs case: {_n(sum(1 for i in info.values() if i['green']), 'run')} "
                   f"ended GREEN, too few to form the view. The rest of the page compares the runs against each other: "
                   f"what each one examined, and what one covered that another did not.")
    elif not case["missing"]:
        alone = any(all(m["cells"][r] for m in matrix) for r in case_runs)
        summary += (" Together the runs in this view cover every requirement" +
                    ("." if alone else ", although no single run does: each one explored different pathways."))
    elif case["missing"]:
        summary += (" A GREEN can still be the right answer, because the code may well be safe; the point is that the "
                    "gateway cannot tell that from the verdicts, because nobody looked.")

    missing = []
    for rid in (case["missing"] or []) if case_runs else []:
        it = next(i for i in items if i["id"] == rid)
        cells = by_id[rid]["cells"]
        elsewhere = [r for r in columns if cells[r] and r not in case_runs]
        if it["kind"] == "V":
            f = it["functions"]
            text = (f"{_fn(f[0])} can return None, and {_fn(f[-1])} uses its result. To check that use, RepoAudit "
                    f"has to carry the None from {_fn(f[0])} into {_fn(f[-1])} and analyse {_fn(f[-1])} with it. None "
                    f"of the {len(case_ra)} RepoAudit runs in this view did.")
            src = a_of.get(f[0])
            if src and by_id.get(src, {}).get("in_case"):
                text += (f" They did examine {_fn(f[0])} itself ({src}), so they saw where the None comes from; they "
                         f"never followed it into {_fn(f[-1])}.")
            text += " Semgrep cannot fill the gap: it does not follow values across functions."
        elif it["kind"] == "A":
            text = (f"No RepoAudit run in this view examined {_fn(it['function'])} as a source of None, so nothing it "
                    f"could return was followed anywhere.")
        else:
            text = f"No Semgrep run in this view scanned {it['file']} with the fixed rules."
        text += (f" Outside this view, {_ids(elsewhere)} did cover it." if elsewhere
                 else " No run in the whole cycle covered it.")
        missing.append({"id": rid, "requirement": plain(it), "explanation": text})
    if not case_runs:
        missing_close = ""
    elif missing:
        missing_close = (f"So the GREENs say nothing about these {len(missing)} requirements. The tools reported no bug "
                         f"there because they did not look, not because they showed the code is safe.")
    else:
        missing_close = "Every requirement is covered by at least one run in this view."

    runs = []
    for r in columns:
        ri = info.get(r)
        if not ri:
            continue
        cov = {k: [i["id"] for i in kinds[k] if by_id[i["id"]]["cells"][r]] for k in "AVS"}
        gap = [m["id"] for m in matrix if m["cells"][r] == 0]
        verdict = ("finished normally and reported no bugs, so its verdict is GREEN" if ri["green"] else
                   f"reported {_n(ri['findings'], 'possible bug')}, so it is not GREEN and a verdict-only gateway would "
                   "already stop" if ri["findings"] else
                   "did not finish normally, so it is not GREEN and a verdict-only gateway would already stop")
        if ri["control"] == "RepoAudit":
            alias = r.split("/")[0]
            yes, no = ri["validator_answers"]["yes"], ri["validator_answers"]["no"]
            text = (f"A RepoAudit run with model slot {alias} ({_model(ri)}). It {verdict}. Behind the verdict: it "
                    f"examined {len(cov['A'])} of {len(kinds['A'])} required functions as None sources and validated "
                    f"{len(cov['V'])} of {len(kinds['V'])} required flows ({_ids(cov['V'])}). In total it made "
                    f"{_n(ri['analysis_units'], 'analysis request')} and "
                    f"{_n(ri['validated_chains'], 'path-validation request')}; the validator answered \"reachable\" "
                    f"{_n(yes, 'time')} and \"not reachable\" {_n(no, 'time')}. File scans are "
                    f"Semgrep's job, so the S requirements are not RepoAudit's to cover.")
        else:
            text = (f"A Semgrep run ({_model(ri)}). It {verdict}. It scanned {len(cov['S'])} of {len(kinds['S'])} "
                    f"required files. As a pattern scanner it cannot examine None sources or flows, so the A and V "
                    f"requirements are outside its reach.")
        if r in case_runs:
            if chosen_by_operator:
                role = "In the view: chosen by the presenter."
            elif ri["control"] == "Semgrep":
                role = "In the view: the GREEN Semgrep run."
            else:
                j = next((p["jaccard"] for p in pair.get("pairwise", []) if sorted(p["pair"]) == sorted(case_ra)), None)
                role = (f"In the view: one of the divergent pair (two GREEN runs of the same model slot whose examined "
                        f"evidence has similarity {j:.2f}, below the threshold τ = {pair.get('tau')})." if j is not None else
                        "In the view: one of the declared pair.")
        elif not case_runs:
            role = "No view: this cycle has no three-GREENs case."
        else:
            extra = [m["id"] for m in matrix if m["cells"][r] and m["id"] in (case["missing"] or [])]
            alias = r.split("/")[0]
            pair_alias = {x.split("/")[0] for x in case_ra}
            why = ("a different model slot, which the pair rule never compares" if alias not in pair_alias
                   else "the view takes only the first divergent pair")
            role = (f"Not in the view ({why})." +
                    (f" It covers {_ids(extra)}, which the view is missing." if extra else ""))
        runs.append({"run": r, "green": ri["green"], "model": _model(ri), "text": text, "role": role,
                     "not_covered": gap})
    return {"summary": summary, "missing": missing, "missing_close": missing_close, "runs": runs}


def _step_text(a: str, b: str, via: str) -> str:
    return (f"None returned by {_fn(a)} carried into {_fn(b)}" if via == "return"
            else f"None passed from {_fn(a)} into {_fn(b)} as an argument")


def pathways(c: Corpus, info: dict, columns: list[str]) -> dict[str, Any]:
    """DR-22: what each RepoAudit run explored on the same code and bug type, side by side."""
    ra = [r for r in columns if info.get(r, {}).get("control") == "RepoAudit"]
    per = {r: c.query.pathway(r) for r in ra}
    validated = {}
    for r in ra:
        for (a, b) in per[r]:
            if any(w["via"] == "validated" for w in c.query.witnesses({"kind": "V", "functions": [a.removeprefix("fn:"),
                                                                                                    b.removeprefix("fn:")]},
                                                                         runs=[r])):
                validated[(r, a, b)] = True
    steps = sorted({k for p in per.values() for k in p}, key=lambda k: (-sum(k in per[r] for r in ra), k))
    rows = []
    for a, b in steps:
        via = next(per[r][(a, b)]["via"] for r in ra if (a, b) in per[r])
        rows.append({"from": a.removeprefix("fn:"), "to": b.removeprefix("fn:"), "via": via,
                     "plain": _step_text(a, b, via),
                     "cells": {r: ("validated" if validated.get((r, a, b)) else "followed") if (a, b) in per[r] else None
                               for r in ra},
                     "in_every_run": all((a, b) in per[r] for r in ra)})
    pairs = []
    for i, x in enumerate(ra):
        for y in ra[i + 1:]:
            u, n = set(per[x]) | set(per[y]), set(per[x]) & set(per[y])
            same = (info[x]["model"], info[x]["temperature"]) == (info[y]["model"], info[y]["temperature"])
            pairs.append({"runs": [x, y], "both_green": info[x]["green"] and info[y]["green"],
                          "relation": "same model, same settings" if same else
                          "same model, other temperature" if info[x]["model"] == info[y]["model"] else "different models",
                          "shared": len(n), "union": len(u), "similarity": round(len(n) / len(u), 4) if u else None,
                          "only_first": len(set(per[x]) - set(per[y])), "only_second": len(set(per[y]) - set(per[x]))})
    green = [r for r in ra if info[r]["green"]]
    gp = [p for p in pairs if p["both_green"] and p["similarity"] is not None]
    lowest = {rel: min((p for p in gp if p["relation"] == rel), key=lambda p: p["similarity"], default=None)
              for rel in ("same model, same settings", "same model, other temperature", "different models")}
    text = (f"All {len(ra)} RepoAudit runs examined the same code for the same bug type, and {len(green)} of them ended "
            f"GREEN. Between them they explored {len(steps)} different pathways; "
            f"{sum(r['in_every_run'] for r in rows)} were explored by every run.")
    for rel, p in lowest.items():
        if p:
            text += (f" {rel.capitalize()}: {p['runs'][0]} and {p['runs'][1]}, both GREEN, share only "
                     f"{p['shared']} of the {p['union']} pathways either of them explored ({p['similarity']:.0%}).")
    if not gp:
        text += " No two GREEN runs can be compared in this cycle."
    return {"runs": ra, "rows": rows, "pairs": pairs, "summary": text}


def _contrast_story(ct: dict, info: dict) -> str:
    a, b = info.get(ct["covering_run"]), info.get(ct["missing_run"])
    if not a or not b:
        return ""
    if a["model"] == b["model"] and a["temperature"] != b["temperature"]:
        diff = (f"Both runs use the same model ({a['model']}); only the temperature differs ({a['temperature']} vs "
                f"{b['temperature']}). Same tool, same code, a different sample of the model, different coverage.")
    elif a["model"] == b["model"]:
        diff = f"Both runs use the same model and settings ({_model(a)}): two runs of one configuration, different coverage."
    else:
        diff = f"Two different models: {_model(a)} against {_model(b)}."
    did, never = ("took this step", "never took it") if ct["kind"] == "V" else ("covered it", "never covered it")
    return (f"{ct['item']}: {ct['requirement_plain']}. Run {ct['covering_run']} ({_model(a)}) {did}; the excerpt "
            f"below is RepoAudit's own log of it, quoted byte for byte from the ledger. Run {ct['missing_run']} "
            f"({_model(b)}) " + (f"also ended GREEN but {never}. "
                                 if b["green"] else "did not (it is not GREEN because of findings elsewhere). ") + diff)


def _run_info(c: Corpus) -> dict[str, dict]:
    info = {}
    for r in c.records.values():
        if r["event_type"] == "harness.run_verdict":
            p, cfg = r["payload"], r.get("config") or {}
            info[r["run"]] = {"run": r["run"], "green": bool(p.get("green")), "findings": p.get("findings"),
                              "control": "Semgrep" if r["run"].startswith("semgrep/") else "RepoAudit",
                              "provider": p.get("provider") or cfg.get("provider"),
                              "model": p.get("requested_model") or cfg.get("model"),
                              "response_models": p.get("response_models_observed") or [],
                              "temperature": cfg.get("temperature")}
    for run in info:
        node = f"run:{run}"
        info[run]["validator_answers"] = {
            "yes": sum(1 for e in c.store.out_edges(node, "answered") if c.store.nodes()[e["dst"]]["attrs"].get("reachable")),
            "no": sum(1 for e in c.store.out_edges(node, "answered") if c.store.nodes()[e["dst"]]["attrs"].get("reachable") is False)}
        info[run]["analysis_units"] = len(c.store.out_edges(node, "observed"))
        info[run]["validated_chains"] = len(c.store.out_edges(node, "validated"))
    return info


def _project_root(c: Corpus, run: str) -> str | None:
    for r in c.records.values():
        if r["run"] == run and r["event_type"] == "harness.run_verdict":
            try:
                man = json.loads(c.ledger.blob(r["source_ref"]["sha256"]))
            except (OSError, ValueError):
                return None
            cmd = man.get("cmd") or []
            if "--project-path" in cmd:
                return cmd[cmd.index("--project-path") + 1]
            return cmd[-1] if cmd else None
    return None


def _redact(text: str, root: str | None) -> str:
    if root:
        text = text.replace(root.rstrip("/") + "/", "")
    return re.sub(r"/(?:Users|home)/[^\s,'\")]+/", "<path>/", text)


def _trim(event_type: str, text: str, max_lines: int = 40) -> str:
    if event_type == "repoaudit.validation_request":
        i = text.rfind("Now I will provide you with the program")
        text = text[i:] if i >= 0 else text
    elif event_type == "repoaudit.analysis_unit":
        i = text.rfind("Now I will give you a target function")
        j = text.find("Where does", i)
        text = text[i:(j if j > i else None)] if i >= 0 else text
    lines = [l.rstrip() for l in text.strip().splitlines()]
    return "\n".join(lines[:max_lines] + (["…"] if len(lines) > max_lines else []))


def excerpt(c: Corpus, refs: list[str], kind: str, function: str | None = None) -> dict[str, Any] | None:
    """The native bytes behind a witness. For a followed flow: the analysis step in the receiving function."""
    cands = [c.records[r] for r in refs if r in c.records and c.records[r]["event_type"] in KIND_EVENT[kind]]
    if function:
        cands.sort(key=lambda r: (r["payload"].get("function") != function.split("::")[-1],
                                  r["event_type"] != "repoaudit.analysis_unit"))
    for r in cands:
        ref = r["record_hash"]
        sr = r["source_ref"]
        data = c.ledger.blob(sr["sha256"])
        if "start" in sr:
            raw = data[sr["start"]:sr["end"]].decode("utf-8", errors="replace")
            loc = f"{sr['file']} bytes {sr['start']}–{sr['end']} (sha256 {sr['sha256'][:12]}…)"
        else:
            doc = json.loads(data or b"{}")
            raw = json.dumps({"paths": doc.get("paths"), "rules": sorted({x.get("check_id") for x in doc.get("results", [])})},
                             indent=2)
            loc = f"{sr['file']} {sr.get('pointer', '')} (sha256 {sr['sha256'][:12]}…)"
        return {"run": r["run"], "event_type": r["event_type"], "location": loc, "ledger_record": ref,
                "text": _trim(r["event_type"], _redact(raw, _project_root(c, r["run"])))}
    return None


def build(cycle: Cycle, item_id: str | None = None, runs: list[str] | None = None) -> dict[str, Any]:
    s4 = cycle.data["stages"]["4"]["outcome"]
    req_path = Path(s4["required_set_path"])
    required = requirements.load(req_path if req_path.is_absolute() else repo_root() / req_path)
    c = open_corpus(cycle)
    info = _run_info(c)
    view = s4["views"]["P5"] if s4["views"]["P5"]["attainable"] else s4["views"]["P7"]
    case_runs = runs or view["runs"]
    others = sorted(r for r in info if r not in case_runs)
    columns = list(case_runs) + others
    matrix = []
    for it in required["items"]:
        cells = {r: len(c.query.witnesses(_req(it), runs=[r])) for r in columns}
        matrix.append({"id": it["id"], "kind": it["kind"], "requirement": describe(it), "plain": plain(it),
                       "cells": cells, "in_case": any(cells[r] for r in case_runs)})
    # contrast: declared rule, or the operator's choice. Without a case (no GREEN run), compare all RepoAudit runs.
    pool = [r for r in case_runs if not r.startswith("semgrep/")] or [r for r in columns if not r.startswith("semgrep/")]
    chosen = None
    if item_id:
        chosen = next((m for m in matrix if m["id"] == item_id), None)
    if chosen is None:
        chosen = next((m for m in matrix if any(m["cells"][r] for r in columns)
                       and any(not m["cells"][r] for r in pool)), None)
    contrast = None
    if chosen:
        item = next(i for i in required["items"] if i["id"] == chosen["id"])
        covering = [r for r in columns if chosen["cells"][r]]
        missing = [r for r in pool if not chosen["cells"][r]] or \
                  [r for r in columns if not chosen["cells"][r]]
        ws = c.query.witnesses(_req(item), runs=covering[:1]) if covering else []
        ex = excerpt(c, ws[0]["refs"], item["kind"], item["functions"][-1] if item["kind"] == "V" else None) if ws else None
        m = missing[0] if missing else None
        fns = [item.get("function")] if item["kind"] == "A" else item.get("functions", [])
        examined = []
        if m:
            for e in c.store.out_edges(f"run:{m}", "observed"):
                for a in c.store.out_edges(e["dst"], "about"):
                    if a["dst"].removeprefix("fn:") in fns:
                        examined.append(f"analysed {a['dst'].removeprefix('fn:')}")
        contrast = {"item": chosen["id"], "requirement": chosen["requirement"], "requirement_plain": plain(item),
                    "kind": item["kind"],
                    "covered_by": covering, "missing_in": missing,
                    "covering_run": covering[0] if covering else None, "missing_run": m,
                    "excerpt": ex,
                    "missing_run_examined": sorted(set(examined)),
                    "missing_run_summary": (f"{m}: {info[m]['analysis_units']} analysis units, {info[m]['validated_chains']} "
                                            f"validated flows in total; none {KIND_TEXT[item['kind']]} for this requirement")
                    if m else None}
    p5 = s4["views"]["P5"]
    case = {"view": "P5" if p5["attainable"] else "P7", "runs": [info[r] for r in case_runs if r in info],
            "verdict_only": view["verdict_only"], "taip": view["observed"], "gateway": view["action"],
            "missing": view["missing"], "oracle": view["oracle"], "oracle_agrees": view["agree"]}
    if runs:  # the presenter's own selection: decide it afresh (TAIP and the independent oracle), never reuse P5's
        d = cycle.path / "stage2" / cycle.data["stages"]["2"]["outcome"]["attempt_dir"] / "corpus"
        v = View("presenter", list(runs), "runs chosen by the presenter")
        got = Evaluator(c.store, c.records, {b.name for b in (d / "blobs").iterdir()}).decide(required, v)
        s1 = stage1_dir(cycle)
        want = oracle.expected(dict(bundles(s1)), required, target_root(s1), [v.manifest()])["presenter"]
        case.update({"view": "presenter's choice", "verdict_only": verdict_only(v, {r: i["green"] for r, i in info.items()}),
                     "taip": got["posture"], "gateway": got["action"], "missing": got["missing"],
                     "oracle": want["posture"],
                     "oracle_agrees": got["posture"] == want["posture"] and got["missing"] == want["missing"]})
    pair_file = cycle.path / "stage4" / s4["attempt_dir"] / "pair-selection.json"
    pair = json.loads(pair_file.read_text()) if pair_file.exists() else {}
    pair["tau"] = s4.get("tau")
    if contrast:
        contrast["story"] = _contrast_story(contrast, info)
    narrative = _narrative(required["items"], matrix, info, case_runs, columns, case, pair, bool(runs))
    paths = pathways(c, info, columns)
    return {"cycle": cycle.id, "mode": cycle.data["mode"], "imported_from": cycle.data.get("imported_from"),
            "case": case, "narrative": narrative, "pathways": paths, "glossary": [{"term": t, "meaning": m} for t, m in GLOSSARY],
            "three_green_case": s4["three_green_case"], "columns": columns, "run_info": info, "matrix": matrix,
            "contrast": contrast, "selection_rule": "first required item covered by some run and missing from a RepoAudit run of the case "
                              "(of any run when the case is empty)",
            "illustrative": True}
