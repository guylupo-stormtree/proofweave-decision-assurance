"""Semgrep adapter: one sealed Stage 1 Semgrep run → evidence observations with source references."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...hashing import sha256_bytes
from .repoaudit import Observation


def parse_run(run_dir: Path) -> tuple[dict[str, Any], list[Observation]]:
    run_dir = Path(run_dir)
    mbytes = (run_dir / "manifest.json").read_bytes()
    man = json.loads(mbytes)
    obs = [Observation("harness.run_verdict", {
        "green": man["green"], "complete": man.get("exit_code") == 0, "findings": man.get("results"),
        "provider": None, "requested_model": None},
        {"file": "manifest.json", "sha256": sha256_bytes(mbytes), "pointer": "/green"}, man.get("start"))]
    data = (run_dir / "semgrep.json").read_bytes() if (run_dir / "semgrep.json").exists() else b""
    try:
        doc = json.loads(data or b"{}")
    except ValueError:
        doc = {}
    sha = sha256_bytes(data)
    root = (man.get("cmd") or [""])[-1].rstrip("/")  # the target directory Semgrep was given

    def rel(path: str | None) -> str | None:
        if path and root and path.startswith(root + "/"):
            return path[len(root) + 1:]
        return path

    scanned = sorted(rel(x) for x in doc.get("paths", {}).get("scanned", []))
    obs.append(Observation("semgrep.scan", {"scanned": scanned, "files_scanned": len(scanned),
                                            "errors": len(doc.get("errors", [])), "version": doc.get("version")},
                           {"file": "semgrep.json", "sha256": sha, "pointer": "/paths"}))
    for i, r in enumerate(doc.get("results", [])):
        obs.append(Observation("semgrep.finding", {"check_id": r.get("check_id"), "file": rel(r.get("path")),
                                                   "line": (r.get("start") or {}).get("line")},
                               {"file": "semgrep.json", "sha256": sha, "pointer": f"/results/{i}"}))
    return man, obs
