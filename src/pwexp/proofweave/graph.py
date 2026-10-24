"""Graph Weaver: deterministic projection of ledger records into the causality graph (t2 → t3).

The graph is derived, never the source of truth: it can always be rebuilt from the ledger, and every
node and edge keeps the ledger record hashes that justify it. Entity resolution links RepoAudit's log
text to code using our own parse of the target snapshot (Python `ast`), independent of RepoAudit;
anything that does not resolve is kept and marked unresolved, and cannot count as coverage.

Node kinds: run, verdict, function, value, unit (analysis unit), chain (validation request),
            answer (validation answer), finding, callsite
Edge kinds: run-observed->unit, unit-about->function, run-reached->value, run-validated->chain,
            chain-step->value (attr i), value-in->function, run-answered->answer,
            run-reported->finding, finding-at->value, finding-involves->function, run-verdict->verdict,
            unit-entered_from->function (the None arrived as that callee's return value),
            run-passed->callsite (the analyser said the None is passed as an argument at that call)

Pathways. RepoAudit follows a None one function at a time. How each analysis unit was reached is read
from the unit's own source expression, parsed with `ast`: the literal None is a source; a call to f means
the None was returned by f into this function; a parameter means it was passed in as an argument. The
caller of an argument step is the function whose flow fact names an argument at a call site of this one.
"""
from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Protocol

from ..hashing import sha256_json


# ----------------------------------------------------------------------------- target index
def call_name(node: ast.AST) -> str | None:
    f = getattr(node, "func", None)
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def entry_of(source: str | None) -> tuple[str, str | None]:
    """How an analysis unit was reached, from its source expression: (source|return|name|unknown, detail)."""
    try:
        e = ast.parse((source or "").strip().strip("`"), mode="eval").body
    except SyntaxError:
        return "unknown", None
    if isinstance(e, ast.Constant) and e.value is None:
        return "source", None
    if isinstance(e, ast.Call):
        return "return", call_name(e)
    if isinstance(e, ast.Name):
        return "name", e.id
    return "unknown", None


@dataclass(frozen=True)
class Function:
    file: str
    name: str
    start: int
    end: int

    @property
    def node_id(self) -> str:
        return f"fn:{self.file}::{self.name}"


class TargetIndex:
    """Functions of a Python target snapshot, from our own `ast` parse."""

    def __init__(self, functions: Iterable[Function] = (), calls: dict[tuple[str, int], set[str]] | None = None,
                 params: dict[str, list[str]] | None = None):
        self.functions = sorted(functions, key=lambda f: (f.file, f.start, f.name))
        self._by_name: dict[str, list[Function]] = {}
        for f in self.functions:
            self._by_name.setdefault(f.name, []).append(f)
        self.calls = calls or {}    # (file, line) -> names of the functions called on that line
        self.params = params or {}  # function node id -> parameter names

    @classmethod
    def from_snapshot(cls, root: Path | None) -> "TargetIndex":
        fns, calls, params = [], {}, {}
        if root and Path(root).is_dir():
            for p in sorted(Path(root).rglob("*.py")):
                rel = p.relative_to(root).as_posix()
                try:
                    tree = ast.parse(p.read_text(errors="replace"))
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        f = Function(rel, node.name, node.lineno, getattr(node, "end_lineno", node.lineno))
                        fns.append(f)
                        a = node.args
                        params[f.node_id] = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
                    elif isinstance(node, ast.Call):
                        name = call_name(node)
                        if name:
                            for line in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                                calls.setdefault((rel, line), set()).add(name)
        return cls(fns, calls, params)

    def by_name(self, name: str | None) -> list[Function]:
        return self._by_name.get(name or "", [])

    def enclosing(self, file: str, line: int) -> Function | None:
        cands = [f for f in self.functions if f.file == file and f.start <= line <= f.end]
        return min(cands, key=lambda f: f.end - f.start) if cands else None


# ----------------------------------------------------------------------------- store
class GraphStore(Protocol):
    watermark: int

    def add_node(self, node_id: str, kind: str, attrs: dict[str, Any], ref: str) -> None: ...
    def add_edge(self, src: str, dst: str, kind: str, attrs: dict[str, Any], ref: str) -> None: ...
    def nodes(self) -> dict[str, dict[str, Any]]: ...
    def edges(self) -> list[dict[str, Any]]: ...


class InMemoryGraphStore:
    """Default GraphStore (Dgraph is reserved as an optional second backend, run B)."""

    def __init__(self):
        self.watermark = -1
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: dict[tuple, dict[str, Any]] = {}
        self._out: dict[str, list[dict[str, Any]]] = {}   # adjacency index: src -> edges
        self._refs: set[str] = set()                      # every materialised ledger record hash

    def add_node(self, node_id, kind, attrs, ref):
        n = self._nodes.setdefault(node_id, {"id": node_id, "kind": kind, "attrs": {}, "refs": []})
        n["attrs"].update(attrs)
        if ref not in n["refs"]:
            n["refs"].append(ref)
        self._refs.add(ref)

    def add_edge(self, src, dst, kind, attrs, ref):
        key = (src, dst, kind, json.dumps(attrs, sort_keys=True))
        e = self._edges.get(key)
        if e is None:
            e = self._edges[key] = {"src": src, "dst": dst, "kind": kind, "attrs": attrs, "refs": []}
            self._out.setdefault(src, []).append(e)
        if ref not in e["refs"]:
            e["refs"].append(ref)
        self._refs.add(ref)

    def out_edges(self, src: str, kind: str | None = None) -> list[dict[str, Any]]:
        return [e for e in self._out.get(src, []) if kind is None or e["kind"] == kind]

    def has_refs(self, refs: Iterable[str]) -> bool:
        return set(refs) <= self._refs

    def nodes(self):
        return self._nodes

    def edges(self):
        return list(self._edges.values())

    # deterministic serialisation
    def snapshot(self) -> dict[str, Any]:
        return {"watermark": self.watermark,
                "nodes": [self._nodes[k] for k in sorted(self._nodes)],
                "edges": sorted(self._edges.values(), key=lambda e: (e["src"], e["dst"], e["kind"],
                                                                     json.dumps(e["attrs"], sort_keys=True)))}

    def graph_hash(self) -> str:
        return sha256_json(self.snapshot())

    def checkpoint(self, path: Path) -> str:
        snap = self.snapshot()
        Path(path).write_text(json.dumps(snap, sort_keys=True, ensure_ascii=False) + "\n")
        return sha256_json(snap)

    @classmethod
    def load(cls, path: Path) -> "InMemoryGraphStore":
        snap = json.loads(Path(path).read_text())
        s = cls()
        s.watermark = snap["watermark"]
        for n in snap["nodes"]:
            s._nodes[n["id"]] = n
            s._refs.update(n["refs"])
        for e in snap["edges"]:
            s._edges[(e["src"], e["dst"], e["kind"], json.dumps(e["attrs"], sort_keys=True))] = e
            s._out.setdefault(e["src"], []).append(e)
            s._refs.update(e["refs"])
        return s


# ----------------------------------------------------------------------------- weaver
@dataclass
class Weaver:
    store: InMemoryGraphStore
    index: TargetIndex = field(default_factory=TargetIndex)

    def _fn_by_name(self, name: str | None, ref: str) -> str:
        cands = self.index.by_name(name)
        if len(cands) == 1:
            f = cands[0]
            self.store.add_node(f.node_id, "function", {"file": f.file, "name": f.name, "resolved": True}, ref)
            return f.node_id
        nid = f"fn?:{name}"
        self.store.add_node(nid, "function", {"name": name, "resolved": False,
                                              "reason": "ambiguous" if cands else "not in target"}, ref)
        return nid

    def _value(self, v: dict[str, Any], ref: str) -> str:
        nid = f"val:{v.get('file')}:{v.get('line')}:{v.get('text')}"
        self.store.add_node(nid, "value", {"file": v.get("file"), "line": v.get("line"), "text": v.get("text")}, ref)
        f = self.index.enclosing(v.get("file") or "", int(v.get("line") or -1))
        if f:
            self.store.add_node(f.node_id, "function", {"file": f.file, "name": f.name, "resolved": True}, ref)
            self.store.add_edge(nid, f.node_id, "in", {}, ref)
        return nid

    def apply(self, records: Iterable[dict[str, Any]]) -> int:
        n = 0
        for r in records:
            if r["seq"] <= self.store.watermark:
                continue
            ref, run, p, et = r["record_hash"], f"run:{r['run']}", r["payload"], r["event_type"]
            self.store.add_node(run, "run", {"run": r["run"], "synthetic": bool(r.get("synthetic"))}, ref)
            node = f"{et.split('.')[-1]}:{r['id']}"
            if et == "harness.run_verdict":
                self.store.add_node(run, "run", {k: p.get(k) for k in ("green", "complete", "findings",
                                                                          "requested_model", "provider")}, ref)
                verdict = "verdict:GREEN" if p.get("green") else "verdict:NOT_GREEN"
                self.store.add_node(verdict, "verdict", {}, ref)
                self.store.add_edge(run, verdict, "verdict", {}, ref)
            elif et == "repoaudit.analysis_unit":
                fn = self._fn_by_name(p.get("function"), ref)
                kind, detail = entry_of(p.get("source"))
                if kind == "name":
                    kind = "parameter" if detail in self.index.params.get(fn, []) else "unknown"
                self.store.add_node(node, "unit", {"function": p.get("function"), "source": p.get("source"),
                                                   "line": p.get("line"), "entry": kind}, ref)
                self.store.add_edge(run, node, "observed", {}, ref)
                self.store.add_edge(node, fn, "about", {}, ref)
                if kind == "return" and len(self.index.by_name(detail)) == 1:
                    self.store.add_edge(node, self._fn_by_name(detail, ref), "entered_from", {}, ref)
            elif et == "repoaudit.flow_fact":
                for v in p.get("values", []):
                    self.store.add_edge(run, self._value(v, ref), "reached", {"label": v.get("label")}, ref)
                    if v.get("label") != "ARG":
                        continue
                    caller = self.index.enclosing(v.get("file") or "", int(v.get("line") or -1))
                    for name in sorted(self.index.calls.get((v.get("file") or "", int(v.get("line") or -1)), ())):
                        if not caller or len(self.index.by_name(name)) != 1:
                            continue
                        callee = self._fn_by_name(name, ref)
                        if callee != caller.node_id:
                            cs = f"callsite:{v.get('file')}:{v.get('line')}:{name}"
                            self.store.add_node(cs, "callsite", {"from": caller.node_id, "to": callee,
                                                                 "file": v.get("file"), "line": v.get("line")}, ref)
                            self.store.add_edge(run, cs, "passed", {}, ref)
            elif et == "repoaudit.validation_request":
                self.store.add_node(node, "chain", {"length": len(p.get("chain", []))}, ref)
                self.store.add_edge(run, node, "validated", {}, ref)
                for i, v in enumerate(p.get("chain", [])):
                    self.store.add_edge(node, self._value(v, ref), "step", {"i": i}, ref)
            elif et == "repoaudit.validation_answer":
                self.store.add_node(node, "answer", {"reachable": p.get("reachable")}, ref)
                self.store.add_edge(run, node, "answered", {}, ref)
            elif et == "repoaudit.finding":
                self.store.add_node(node, "finding", {"bug_type": p.get("bug_type")}, ref)
                self.store.add_edge(run, node, "reported", {}, ref)
                bv = p.get("buggy_value") or {}
                if bv.get("file"):
                    self.store.add_edge(node, self._value(bv, ref), "at", {}, ref)
                for fn in p.get("functions", []):
                    f = next((x for x in self.index.by_name(fn.get("name")) if x.file == fn.get("file")), None)
                    self.store.add_edge(node, f.node_id if f else self._fn_by_name(fn.get("name"), ref), "involves", {}, ref)
            elif et == "semgrep.scan":
                self.store.add_node(node, "scan", {k: v for k, v in p.items() if not isinstance(v, (list, dict))}, ref)
                self.store.add_edge(run, node, "scanned", {}, ref)
                for f in p.get("scanned", []):
                    self.store.add_node(f"file:{f}", "file", {"file": f}, ref)
                    self.store.add_edge(node, f"file:{f}", "covers", {}, ref)
            elif et == "semgrep.finding":
                self.store.add_node(node, "finding", {"check_id": p.get("check_id"), "file": p.get("file"),
                                                      "line": p.get("line"), "producer": "semgrep"}, ref)
                self.store.add_edge(run, node, "reported", {}, ref)
                if p.get("file"):
                    self.store.add_edge(node, f"file:{p['file']}", "in_file", {}, ref)
                    f = self.index.enclosing(p["file"], int(p.get("line") or -1))
                    if f:
                        self.store.add_edge(node, f.node_id, "involves", {}, ref)
            self.store.watermark = r["seq"]
            n += 1
        return n
