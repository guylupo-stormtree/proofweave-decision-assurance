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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..cycles import Cycle
from ..paths import repo_root
from ..proofweave.graph import InMemoryGraphStore
from ..proofweave.ledger import Ledger
from ..proofweave.query import QueryAPI
from ..taip import requirements

KIND_EVENT = {"A": "repoaudit.analysis_unit", "V": "repoaudit.validation_request", "S": "semgrep.scan"}
KIND_TEXT = {"A": "analysed", "V": "validated the flow", "S": "scanned with the pinned rules"}


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
        return "flow " + " → ".join(item["functions"]) + " validated"
    return f"{item['file']} scanned by the fixed rules"


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


def excerpt(c: Corpus, refs: list[str], kind: str) -> dict[str, Any] | None:
    for ref in refs:
        r = c.records.get(ref)
        if not r or r["event_type"] != KIND_EVENT[kind]:
            continue
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
        matrix.append({"id": it["id"], "kind": it["kind"], "requirement": describe(it), "cells": cells,
                       "in_case": any(cells[r] for r in case_runs)})
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
        ex = excerpt(c, ws[0]["refs"], item["kind"]) if ws else None
        m = missing[0] if missing else None
        fns = [item.get("function")] if item["kind"] == "A" else item.get("functions", [])
        examined = []
        if m:
            for e in c.store.out_edges(f"run:{m}", "observed"):
                for a in c.store.out_edges(e["dst"], "about"):
                    if a["dst"].removeprefix("fn:") in fns:
                        examined.append(f"analysed {a['dst'].removeprefix('fn:')}")
        contrast = {"item": chosen["id"], "requirement": chosen["requirement"], "kind": item["kind"],
                    "covered_by": covering, "missing_in": missing,
                    "covering_run": covering[0] if covering else None, "missing_run": m,
                    "excerpt": ex,
                    "missing_run_examined": sorted(set(examined)),
                    "missing_run_summary": (f"{m}: {info[m]['analysis_units']} analysis units, {info[m]['validated_chains']} "
                                            f"validated flows in total; none {KIND_TEXT[item['kind']]} for this requirement")
                    if m else None}
    p5 = s4["views"]["P5"]
    return {"cycle": cycle.id, "mode": cycle.data["mode"], "imported_from": cycle.data.get("imported_from"),
            "case": {"view": "P5" if p5["attainable"] else "P7", "runs": [info[r] for r in case_runs if r in info],
                     "verdict_only": view["verdict_only"], "taip": view["observed"], "gateway": view["action"],
                     "missing": view["missing"], "oracle": view["oracle"], "oracle_agrees": view["agree"]},
            "three_green_case": s4["three_green_case"], "columns": columns, "run_info": info, "matrix": matrix,
            "contrast": contrast, "selection_rule": "first required item covered by some run and missing from a RepoAudit run of the case "
                              "(of any run when the case is empty)",
            "illustrative": True}
