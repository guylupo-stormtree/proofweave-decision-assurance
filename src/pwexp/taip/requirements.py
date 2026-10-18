"""The independently declared required set R (mixed granularity; reviewed by a person; locked before acquisition).

File format (JSON):
  {"version": 1, "target": "<repo-relative snapshot>", "derivation": "...", "review": {...},
   "items": [
     {"id": "R01", "kind": "A", "function": "<file>::<name>", "why": "..."},           analysed
     {"id": "R10", "kind": "V", "functions": ["<file>::<a>", "<file>::<b>"], "why": ""},  flow validated
     {"id": "R20", "kind": "S", "file": "<file>", "why": "..."}                            rule-scanned
   ]}
`draft()` derives candidate items from our own `ast` parse of the target, never from RepoAudit output:
  A  every function containing a None source (`return None`, `x = None`) or binding a call result
  V  every call edge caller → callee where the callee contains a None source and the caller uses the result
  S  every Python file in the target
The draft is a starting point for human review; the reviewed file is what the protocol locks.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

KINDS = {"A": ("function",), "V": ("functions",), "S": ("file",)}


class RequirementError(ValueError):
    pass


def load(path: Path) -> dict[str, Any]:
    doc = json.loads(Path(path).read_text())
    errs = problems(doc)
    if errs:
        raise RequirementError("invalid required set:\n  " + "\n  ".join(errs))
    return doc


def problems(doc: dict[str, Any]) -> list[str]:
    out, seen = [], set()
    items = doc.get("items")
    if not isinstance(items, list) or not items:
        return ["items: must be a non-empty list (an empty required set would allow a vacuous PASS)"]
    for i, it in enumerate(items):
        rid, kind = it.get("id"), it.get("kind")
        if not rid or rid in seen:
            out.append(f"item {i}: missing or duplicate id {rid!r}")
        seen.add(rid)
        if kind not in KINDS:
            out.append(f"{rid}: kind must be one of {sorted(KINDS)}")
            continue
        for f in KINDS[kind]:
            if not it.get(f):
                out.append(f"{rid}: kind {kind} needs '{f}'")
        if kind == "V" and len(it.get("functions") or []) < 2:
            out.append(f"{rid}: a V item needs at least two functions in flow order")
    return out


def _none_source(fn: ast.AST) -> bool:
    for n in ast.walk(fn):
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant) and n.value.value is None:
            return True
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and n.value.value is None:
            return True
    return False


def draft(target: Path) -> dict[str, Any]:
    target = Path(target)
    funcs: dict[str, tuple[str, ast.AST]] = {}
    files = []
    for p in sorted(target.rglob("*.py")):
        rel = p.relative_to(target).as_posix()
        files.append(rel)
        tree = ast.parse(p.read_text(errors="replace"))
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.setdefault(n.name, (rel, n))
    sources = {name for name, (_, n) in funcs.items() if _none_source(n)}
    items, edges = [], []
    for name, (rel, n) in sorted(funcs.items(), key=lambda kv: (kv[1][0], kv[1][1].lineno)):
        binds_call = any(isinstance(x, ast.Assign) and isinstance(x.value, ast.Call) for x in ast.walk(n))
        if name in sources or binds_call:
            items.append({"kind": "A", "function": f"{rel}::{name}",
                          "why": "contains a None source" if name in sources else "binds a call result that may be None"})
        for c in ast.walk(n):
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id in sources and c.func.id != name:
                callee_rel = funcs[c.func.id][0]
                edges.append((f"{callee_rel}::{c.func.id}", f"{rel}::{name}"))
    for a, b in sorted(set(edges)):
        items.append({"kind": "V", "functions": [a, b], "why": "None-returning callee flows into caller"})
    for f in files:
        items.append({"kind": "S", "file": f, "why": "file scanned by the pinned fixed rules"})
    for i, it in enumerate(items, 1):
        it["id"] = f"R{i:02d}"
    return {"version": 1, "target": target.as_posix(), "items": [{"id": it.pop("id"), **it} for it in items],
            "derivation": "pwexp required-set draft: own ast parse of the target (independent of RepoAudit output)",
            "review": {"status": "DRAFT: requires human review before locking", "by": None, "date": None}}
