"""RepoAudit adapter: one sealed Stage 1 run → evidence observations with exact source references.

Reads only the run's native files (dfbscan.log, detect_info.json) and its harness manifest. Every
observation carries `source_ref = {file, sha256, start, end}`: the byte span of the native log entry (or
the JSON pointer into detect_info.json) it was taken from, so any ledger record or graph edge can be
traced back to RepoAudit's own output. Nothing is inferred that the native output does not state; in
particular, parallel workers interleave responses, so only self-describing entries are attributed.

Observation types (event_type):
  harness.run_verdict           completion, GREEN (DR-11), findings count, model context   (manifest.json)
  repoaudit.analysis_unit       IntraDataFlowAnalyzer target: function, source expression, line (prompt entry)
  repoaudit.flow_fact           IntraDataFlowAnalyzer output: reachable values per path, with file/line/label
  repoaudit.validation_request  PathValidator candidate chain: ordered values with file/line   (prompt entry)
  repoaudit.validation_answer   PathValidator answer (reachable yes/no); not pairable to a request
  repoaudit.finding             accepted bug report: buggy value, relevant functions          (detect_info.json)
Absolute paths are kept here exactly as RepoAudit wrote them; Bind applies privacy treatment.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...hashing import sha256_bytes

ENTRY = re.compile(rb"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+ - [A-Z]+ - ", re.M)
TIME = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+)")
INTRA_TARGET = re.compile(
    r"Now I will give you a target function with the source point [`'](?P<src>.*?)[`'] at line (?P<line>\d+):\s*```\w*\s*\n(?P<code>.*?)```",
    re.S)
DEF = re.compile(r"^\s*(?:\d+\.\s*)?(?:async\s+)?def\s+(\w+)|^\s*(?:\d+\.\s*)?func\s+(?:\([^)]*\)\s*)?(\w+)", re.M)
VALUE = re.compile(r"\(\((?P<val>.*?), (?P<file>/[^,]*?), (?P<line>-?\d+), (?P<idx>-?\d+)\), ValueLabel\.(?P<label>\w+)\)")
VALIDATOR_Q = "does the following data-flow propagation path"
ANSWER = re.compile(r"Is reachable:\s*(True|False)")


@dataclass
class Observation:
    event_type: str
    payload: dict[str, Any]
    source_ref: dict[str, Any]
    time: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


def _values(text: str) -> list[dict[str, Any]]:
    return [{"text": m["val"], "file": m["file"], "line": int(m["line"]), "index": int(m["idx"]), "label": m["label"]}
            for m in VALUE.finditer(text)]


def _entries(data: bytes):
    starts = [m.start() for m in ENTRY.finditer(data)] + [len(data)]
    for a, z in zip(starts, starts[1:]):
        yield a, z, data[a:z].decode("utf-8", errors="replace")


def parse_log(data: bytes, file_name: str = "dfbscan.log") -> list[Observation]:
    file_sha = sha256_bytes(data)
    obs: list[Observation] = []
    for a, z, text in _entries(data):
        head = text.split("\n", 1)[0]
        t = TIME.match(head)
        ref = {"file": file_name, "sha256": file_sha, "start": a, "end": z}
        when = t.group(1) if t else None
        if " - Prompt:" in head:
            if VALIDATOR_Q in text:
                tail = text.split(VALIDATOR_Q, 1)[1]
                chain = _values(tail)
                if chain:
                    obs.append(Observation("repoaudit.validation_request", {"chain": chain}, ref, when))
            else:
                targets = list(INTRA_TARGET.finditer(text))
                if targets:
                    tg = targets[-1]  # earlier matches are few-shot examples in the prompt template
                    d = DEF.search(tg["code"])
                    fn = (d.group(1) or d.group(2)) if d else None
                    obs.append(Observation("repoaudit.analysis_unit",
                                           {"function": fn, "source": tg["src"], "line": int(tg["line"]),
                                            "function_resolved_by": "def-line" if fn else "unresolved"}, ref, when))
        elif "Output of intra-procedural data-flow analyzer:" in head:
            body = text.split("analyzer:", 1)[1]
            # one set per execution path: "[set(...), {...}]"
            paths = [_values(chunk) for chunk in re.split(r"\}\s*,\s*(?:\{|set\()", body)]
            obs.append(Observation("repoaudit.flow_fact", {"paths": [p for p in paths], "values": _values(body)}, ref, when))
        elif "Output of path_validator:" in head:
            m = ANSWER.search(text)
            if m:
                obs.append(Observation("repoaudit.validation_answer", {"reachable": m.group(1) == "True"}, ref, when))
    return obs


def parse_detect_info(data: bytes, file_name: str = "detect_info.json") -> list[Observation]:
    file_sha = sha256_bytes(data)
    doc = json.loads(data or b"{}")
    items = doc.items() if isinstance(doc, dict) else enumerate(doc)
    obs = []
    for key, rep in items:
        rf = rep.get("relevant_functions") or [[], [], []]
        files, names = (rf[0], rf[1]) if len(rf) >= 2 else ([], [])
        bv = _values(str(rep.get("buggy_value", "")))
        obs.append(Observation("repoaudit.finding", {
            "bug_type": rep.get("bug_type"), "buggy_value": bv[0] if bv else {"text": rep.get("buggy_value")},
            "functions": [{"file": f, "name": n} for f, n in zip(files, names)]},
            {"file": file_name, "sha256": file_sha, "pointer": f"/{key}"}))
    return obs


def parse_run(run_dir: Path) -> tuple[dict[str, Any], list[Observation]]:
    """Return (run manifest, observations) for one Stage 1 RepoAudit run directory."""
    run_dir = Path(run_dir)
    man = json.loads((run_dir / "manifest.json").read_text())
    mbytes = (run_dir / "manifest.json").read_bytes()
    obs = [Observation("harness.run_verdict", {
        "green": man["green"], "complete": man["complete"], "findings": man["findings"],
        "detect_info_source": man.get("detect_info_source"), "provider": man.get("provider"),
        "requested_model": man.get("requested_model"),
        "response_models_observed": man.get("response_models_observed", [])},
        {"file": "manifest.json", "sha256": sha256_bytes(mbytes), "pointer": "/green"}, man.get("start"))]
    if (run_dir / "dfbscan.log").exists():
        obs += parse_log((run_dir / "dfbscan.log").read_bytes())
    if (run_dir / "detect_info.json").exists():
        obs += parse_detect_info((run_dir / "detect_info.json").read_bytes())
    return man, obs


def project_root_of(man: dict[str, Any]) -> str | None:
    """The --project-path RepoAudit was given (used by Bind to make paths repository-relative)."""
    cmd = man.get("cmd") or []
    return cmd[cmd.index("--project-path") + 1] if "--project-path" in cmd else None
