"""Tool environments for re-acquiring evidence (Stage 1). Python only (DR-17).

  vendor/RepoAudit            pinned submodule (Purdue licence: referenced, never vendored or modified)
  vendor/.venv-repoaudit      RepoAudit's own interpreter + dependencies; tree-sitter grammars built once
  vendor/.venv-semgrep        Semgrep CE at the protocol's pinned version

Reviewing, verifying and replaying (Stages 2-4) need none of this.
Building RepoAudit's grammars needs git, network access and a C compiler (one-time).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

from .paths import repo_root

REPOAUDIT_COMMIT = "160f5bcd378a02a2417e32e999f93ef5fa0f5e64"
# RepoAudit's runtime imports for dfbscan (torch/transformers/streamlit are not needed).
REPOAUDIT_DEPS = ["tree-sitter>=0.20.0,<0.22.0", "openai", "anthropic", "google-generativeai", "tiktoken",
                  "networkx", "tqdm", "boto3", "botocore", "setuptools"]


class SetupError(Exception):
    pass


def vendor() -> Path:
    return repo_root() / "vendor"


def repoaudit_dir() -> Path:
    return vendor() / "RepoAudit"


def _bin(env: Path, name: str) -> Path:
    return env / ("Scripts" if os.name == "nt" else "bin") / (name + (".exe" if os.name == "nt" else ""))


def repoaudit_python() -> Path:
    return _bin(vendor() / ".venv-repoaudit", "python")


def semgrep_bin() -> Path:
    return _bin(vendor() / ".venv-semgrep", "semgrep")


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SetupError(f"command failed: {' '.join(cmd)}\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")


def subject_state() -> dict[str, object]:
    """Pinned commit and no modified tracked files (checked before and after every Stage 1)."""
    d = repoaudit_dir()
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=d,
                           capture_output=True, text=True).stdout.strip()
    return {"head": head, "pinned": head == REPOAUDIT_COMMIT, "tracked_files_modified": bool(dirty)}


def grammars_built() -> bool:
    return (repoaudit_dir() / "lib" / "build" / "my-languages.so").exists()


def ensure_repoaudit(log=print) -> None:
    d = repoaudit_dir()
    if not (d / "src" / "repoaudit.py").exists():
        log("fetching RepoAudit submodule …")
        _run(["git", "submodule", "update", "--init", "vendor/RepoAudit"], cwd=repo_root())
    st = subject_state()
    if not st["pinned"]:
        _run(["git", "checkout", "-q", REPOAUDIT_COMMIT], cwd=d)
    env = vendor() / ".venv-repoaudit"
    if not repoaudit_python().exists():
        if sys.version_info < (3, 11):
            raise SetupError("Python 3.11+ required")
        log(f"creating {env.relative_to(repo_root())} …")
        venv.EnvBuilder(with_pip=True).create(env)
        _run([str(repoaudit_python()), "-m", "pip", "install", "-q", "--upgrade", "pip"])
        _run([str(repoaudit_python()), "-m", "pip", "install", "-q", *REPOAUDIT_DEPS])
    if not grammars_built():
        if not shutil.which("git") or not (shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")):
            raise SetupError("building RepoAudit's tree-sitter grammars needs git and a C compiler")
        log("building tree-sitter grammars (one-time) …")
        _run([str(repoaudit_python()), "build.py"], cwd=d / "lib")
    st = subject_state()
    if not st["pinned"] or st["tracked_files_modified"]:
        raise SetupError(f"RepoAudit is not at the pinned, unmodified state: {st}")


def ensure_semgrep(version: str, log=print) -> None:
    env = vendor() / ".venv-semgrep"
    if semgrep_bin().exists():
        have = subprocess.run([str(semgrep_bin()), "--version"], capture_output=True, text=True).stdout.strip()
        if have == version:
            return
        log(f"semgrep {have} installed; switching to pinned {version} …")
    else:
        log(f"creating {env.relative_to(repo_root())} …")
        venv.EnvBuilder(with_pip=True).create(env)
    _run([str(_bin(env, "python")), "-m", "pip", "install", "-q", f"semgrep=={version}"])
