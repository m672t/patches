"""Obtain pristine source trees for both versions and the patch diff between them."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .diffparse import DEFAULT_EXCLUDE, make_tree_diff
from .util import sha256_tree


class SourceError(Exception):
    pass


@dataclass
class VersionSrc:
    name: str
    src_dir: Path
    kind: str                 # dir | git
    version_id: str           # commit hash (git) or tree digest (dir)
    origin: str
    dirty: bool = False


def _git(*args, cwd=None) -> str:
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SourceError(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def prepare_version(name: str, spec: dict, workdir: Path, base_dir: Path) -> VersionSrc:
    dest = workdir / "src" / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if spec.get("git"):
        g = spec["git"]
        repo = (base_dir / g.get("repo", ".")).resolve()
        commit = _git("rev-parse", "--verify", g["rev"] + "^{commit}", cwd=repo).strip()
        dest.mkdir()
        tar = subprocess.run(f"git -C '{repo}' archive {commit} | tar -x -C '{dest}'",
                             shell=True, capture_output=True, text=True)
        if tar.returncode != 0:
            raise SourceError(f"git archive failed for {name}: {tar.stderr.strip()}")
        sub = g.get("subdir")
        if sub:
            tmp = dest.with_name(name + "_sub")
            shutil.move(str(dest / sub), str(tmp))
            shutil.rmtree(dest)
            shutil.move(str(tmp), str(dest))
        return VersionSrc(name, dest, "git", commit, f"{repo}@{g['rev']}")
    src = (base_dir / spec["path"]).resolve()
    if not src.is_dir():
        raise SourceError(f"source dir for {name} not found: {src}")
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns(".git"))
    return VersionSrc(name, dest, "dir", sha256_tree(src), str(src))


def compute_diff(base: VersionSrc, patched: VersionSrc, diff_cfg: dict, base_dir: Path) -> tuple[str, str]:
    """Return (diff_text, origin). Order: explicit patch file > git diff (same repo) > tree diff."""
    if diff_cfg.get("file"):
        p = (base_dir / diff_cfg["file"]).resolve()
        if not p.is_file():
            raise SourceError(f"patch file not found: {p}")
        return p.read_text(errors="replace"), f"file:{p}"
    exclude = diff_cfg.get("exclude", DEFAULT_EXCLUDE)
    return make_tree_diff(base.src_dir, patched.src_dir, exclude), "tree-diff"
