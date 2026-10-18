"""Repository and records locations. Override the root with PWEXP_ROOT (tests, reviewers)."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path


def repo_root() -> Path:
    env = os.environ.get("PWEXP_ROOT")
    if env:
        return Path(env).resolve()
    return Path(__file__).resolve().parents[2]


def records_dir() -> Path:
    return repo_root() / "records"


def cycles_dir() -> Path:
    """Local cycles (maintainer pilots, reviewer cycles): git-ignored."""
    return records_dir() / "cycles"


def published_dir() -> Path:
    """The master set behind the paper: written only by the maintainer's publish action."""
    return records_dir() / "published"


def protocol_dir() -> Path:
    return repo_root() / "protocol"


def code_commit() -> dict[str, object]:
    """Commit and dirty flag of the harness code, stamped into every record (DR-02)."""
    root = repo_root()
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10)
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "src", "protocol"], cwd=root,
                               capture_output=True, text=True, timeout=10)
        commit = head.stdout.strip() if head.returncode == 0 else "uncommitted"
        return {"commit": commit or "uncommitted", "dirty": bool(dirty.stdout.strip())}
    except (OSError, subprocess.SubprocessError):
        return {"commit": "unknown", "dirty": True}
