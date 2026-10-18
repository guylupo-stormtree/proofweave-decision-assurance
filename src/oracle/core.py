"""Oracle implementation. Standard library only; no pwexp imports."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

_TARGET_FN = re.compile(r"target function with the source point [`'][^`']*[`'] at line \d+:\s*```[^\n]*\n(.*?)```", re.S)
_DEF = re.compile(r"^\s*(?:\d+\.\s*)?def\s+([A-Za-z_]\w*)", re.M)
_VAL = re.compile(r"\(\((.*?), (/[^,]*?), (-?\d+), (-?\d+)\), ValueLabel\.\w+\)")
_SPLIT = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+ - [A-Z]+ - ", re.M)
_QUESTION = "does the following data-flow propagation path"


class _Target:
    def __init__(self, root: Path):
        self.by_name: dict[str, list[tuple[str, int, int]]] = {}
        for p in sorted(Path(root).rglob("*.py")):
            rel = p.relative_to(root).as_posix()
            for n in ast.walk(ast.parse(p.read_text(errors="replace"))):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.by_name.setdefault(n.name, []).append((rel, n.lineno, n.end_lineno or n.lineno))

    def unique(self, name: str) -> str | None:
        c = self.by_name.get(name, [])
        return f"{c[0][0]}::{name}" if len(c) == 1 else None

    def at(self, rel: str, line: int) -> str | None:
        best = None
        for name, defs in self.by_name.items():
            for f, a, b in defs:
                if f == rel and a <= line <= b and (best is None or b - a < best[1]):
                    best = (f"{f}::{name}", b - a)
        return best[0] if best else None


def _relpath(path: str, root: str) -> str:
    root = root.rstrip("/")
    return path[len(root) + 1:] if root and path.startswith(root + "/") else path


def _evidence(bundle: Path, target: _Target) -> dict:
    """What one native run evidences: analysed functions, validated flows, scanned files, findings."""
    man = json.loads((bundle / "manifest.json").read_text())
    ev = {"A": set(), "V": [], "S": set(), "bad_fns": set(), "bad_files": set()}
    if (bundle / "semgrep.json").exists():
        root = (man.get("cmd") or [""])[-1]
        doc = json.loads((bundle / "semgrep.json").read_text() or "{}")
        ev["S"] = {_relpath(p, root) for p in doc.get("paths", {}).get("scanned", [])}
        for r in doc.get("results", []):
            f = _relpath(r.get("path", ""), root)
            ev["bad_files"].add(f)
            fn = target.at(f, (r.get("start") or {}).get("line", -1))
            if fn:
                ev["bad_fns"].add(fn)
        return ev
    cmd = man.get("cmd") or []
    root = cmd[cmd.index("--project-path") + 1] if "--project-path" in cmd else ""
    text = (bundle / "dfbscan.log").read_text(errors="replace") if (bundle / "dfbscan.log").exists() else ""
    for entry in _SPLIT.split(text):
        head = entry.split("\n", 1)[0]
        if not head.startswith("Prompt:"):
            continue
        if _QUESTION in entry:
            chain = []
            for _, path, line, _ in _VAL.findall(entry.split(_QUESTION, 1)[1]):
                fn = target.at(_relpath(path, root), int(line))
                if fn and (not chain or chain[-1] != fn):
                    chain.append(fn)
            if chain:
                ev["V"].append(chain)
        else:
            m = _TARGET_FN.findall(entry)
            if m:
                d = _DEF.search(m[-1])
                fn = target.unique(d.group(1)) if d else None
                if fn:
                    ev["A"].add(fn)
    if (bundle / "detect_info.json").exists():
        for rep in json.loads((bundle / "detect_info.json").read_text() or "{}").values():
            files, names = (rep.get("relevant_functions") or [[], []])[:2]
            for f, n in zip(files, names):
                ev["bad_fns"].add(f"{_relpath(f, root)}::{n}")
    return ev


def _covered(item: dict, ev: dict) -> bool:
    if item["kind"] == "A":
        return item["function"] in ev["A"]
    if item["kind"] == "S":
        return item["file"] in ev["S"]
    want = item["functions"]
    for chain in ev["V"]:
        it = iter(chain)
        if all(w in it for w in want):
            return True
    return False


def _violated(item: dict, ev: dict) -> bool:
    if item["kind"] == "S":
        return item["file"] in ev["bad_files"]
    fns = [item["function"]] if item["kind"] == "A" else item["functions"]
    return any(f in ev["bad_fns"] for f in fns)


def expected(bundles: dict[str, Path], required: dict, target_root: Path, views: list[dict]) -> dict[str, dict]:
    """Expected decision per view. `bundles` maps run tag -> native bundle directory."""
    target = _Target(target_root)
    evidence = {tag: _evidence(path, target) for tag, path in bundles.items()}
    out = {}
    for v in views:
        if not v.get("attainable", True):
            out[v["id"]] = {"posture": None, "action": None, "attainable": False}
            continue
        usable = [r for r in v["runs"] if r in evidence and r not in v.get("incompatible_runs", [])]
        states = {}
        for item in required.get("items", []):
            rid = item["id"]
            if any(_violated(item, evidence[r]) for r in usable):
                states[rid] = "FAIL"
                continue
            if rid in v.get("withheld", []):
                states[rid] = "INCONCLUSIVE"
                continue
            ok = any(_covered(item, evidence[r]) for r in usable if rid not in v.get("mutated", {}).get(r, []))
            states[rid] = "PASS" if ok else "INCONCLUSIVE"
        vals = list(states.values())
        posture = "INCONCLUSIVE" if not vals else "FAIL" if "FAIL" in vals else \
            "PASS" if all(x == "PASS" for x in vals) else "INCONCLUSIVE"
        out[v["id"]] = {"posture": posture, "action": "PROCEED" if posture == "PASS" else "HOLD",
                        "missing": sorted(k for k, x in states.items() if x == "INCONCLUSIVE"), "attainable": True}
    return out
