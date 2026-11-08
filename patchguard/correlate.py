"""Finding-to-Patch correlation: tie stack frames / executed lines to what the patch changed.

Levels (strongest first):
  direct_line        a stack frame sits ON a line the patch removed/added/modified
  changed_function   a stack frame is inside a function the patch touched (not on a changed line)
  execution_path     coverage shows the run executed changed lines AND outcome differs between versions
  near_line          frame within NEAR lines of a change -> WEAK (adjacency alone is not evidence)
  changed_file       frame in a changed file only -> WEAK
  unknown            not enough evidence (reported honestly, never guessed)
"""
from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from pathlib import Path

from .diffparse import FileDiff
from .srcmap import Func, enclosing, find_functions, norm_func

NEAR = 3
RANK = {"direct_line": 0, "changed_function": 1, "execution_path": 2, "near_line": 3,
        "changed_file": 4, "unknown": 9}
LINKED = {"direct_line", "changed_function", "execution_path"}


@dataclass
class FileEntry:
    diff: FileDiff
    old_changed: set = field(default_factory=set)
    new_changed: set = field(default_factory=set)
    old_anchors: set = field(default_factory=set)
    new_anchors: set = field(default_factory=set)
    old_funcs: list = field(default_factory=list)
    new_funcs: list = field(default_factory=list)
    old_changed_funcs: set = field(default_factory=set)   # normalised names
    new_changed_funcs: set = field(default_factory=set)

    def side(self, s):  # "base"|"patched"
        return (self.old_changed, self.old_anchors, self.old_funcs, self.old_changed_funcs) if s == "base" \
            else (self.new_changed, self.new_anchors, self.new_funcs, self.new_changed_funcs)


class DiffIndex:
    def __init__(self, files: list[FileDiff], base_src: Path, patched_src: Path):
        self.entries: list[FileEntry] = []
        for fd in files:
            if fd.binary:
                continue
            e = FileEntry(fd)
            for h in fd.hunks:
                e.old_changed.update(h.removed)
                e.new_changed.update(h.added)
                e.old_anchors.update(h.old_anchors)
                e.new_anchors.update(h.new_anchors)
            e.old_funcs = self._funcs(base_src, fd.old_path)
            e.new_funcs = self._funcs(patched_src, fd.new_path)
            for ln in e.old_changed | e.old_anchors:
                f = enclosing(e.old_funcs, ln)
                if f:
                    e.old_changed_funcs.add(norm_func(f.name))
            for ln in e.new_changed | e.new_anchors:
                f = enclosing(e.new_funcs, ln)
                if f:
                    e.new_changed_funcs.add(norm_func(f.name))
            # fall back to hunk-header function hints when parsing found nothing
            for h in fd.hunks:
                hint = norm_func(h.section) if "(" in h.section else None
                if hint:
                    if not e.old_funcs:
                        e.old_changed_funcs.add(hint)
                    if not e.new_funcs:
                        e.new_changed_funcs.add(hint)
            self.entries.append(e)

    @staticmethod
    def _funcs(root: Path, rel: str | None) -> list[Func]:
        if not rel or not (root / rel).is_file():
            return []
        try:
            return find_functions((root / rel).read_text(errors="replace"))
        except Exception:
            return []

    def lookup(self, frame_path: str | None, side: str) -> FileEntry | None:
        if not frame_path:
            return None
        fp = posixpath.normpath(frame_path.replace("\\", "/"))
        best, best_score = None, 0
        for e in self.entries:
            rel = e.diff.old_path if side == "base" else e.diff.new_path
            rel = rel or e.diff.path
            if not rel:
                continue
            fparts, rparts = fp.split("/"), rel.split("/")
            score = 0
            while score < min(len(fparts), len(rparts)) and fparts[-1 - score] == rparts[-1 - score]:
                score += 1
            if score >= 1 and score == len(rparts) or (score >= 1 and score == len(fparts)):
                if score > best_score:
                    best, best_score = e, score
        return best

    def summary(self) -> dict:
        files = []
        for e in self.entries:
            files.append({
                "path": e.diff.path, "old_path": e.diff.old_path, "status": e.diff.status,
                "hunks": [{"old": [h.old_start, h.old_len], "new": [h.new_start, h.new_len],
                           "section": h.section, "removed": h.removed, "added": h.added} for h in e.diff.hunks],
                "changed_functions": {"base": sorted(x for x in e.old_changed_funcs if x),
                                      "patched": sorted(x for x in e.new_changed_funcs if x)},
            })
        return {"files": files,
                "stats": {"files_changed": len(files),
                          "lines_removed": sum(len(e.old_changed) for e in self.entries),
                          "lines_added": sum(len(e.new_changed) for e in self.entries)}}


def correlate_frames(frames: list[dict], index: DiffIndex, side: str) -> dict | None:
    """Best evidence relating one stack (app frames only) to the diff, on `side` (base|patched)."""
    best = None
    for depth, fr in enumerate(frames):
        e = index.lookup(fr.get("file"), side)
        if e is None:
            continue
        changed, anchors, funcs, changed_funcs = e.side(side)
        line, fn = fr.get("line"), norm_func(fr.get("function"))
        if fn is None and line and funcs:
            enc = enclosing(funcs, line)
            fn = norm_func(enc.name) if enc else None
        detail = None
        if line in changed:
            level = "direct_line"
            detail = "frame is on a line the patch modified"
        elif line in anchors:
            level = "direct_line"
            detail = "patch inserted/removed code exactly at this frame's statement (guard before the failing line)"
        elif fn and fn in changed_funcs:
            level = "changed_function"
        elif line and any(abs(line - c) <= NEAR for c in (changed | anchors)):
            level = "near_line"
        else:
            level = "changed_file"
        ev = {"type": "stack_frame", "level": level, "side": side, "stack_depth": depth,
              "file": e.diff.path, "function": fr.get("function"), "line": line,
              "changed_lines_in_file": sorted(changed)[:20], "detail": detail}
        if best is None or (RANK[level], depth) < (RANK[best["level"]], best["stack_depth"]):
            best = ev
    return best


def correlate_coverage(cov_base: dict | None, cov_patched: dict | None, index: DiffIndex,
                       outcome_differs: bool) -> dict | None:
    """Execution-path evidence from gcov: did each run execute lines the patch touched?"""
    if cov_base is None and cov_patched is None:
        return None
    hit = {"base": {}, "patched": {}}
    for e in index.entries:
        for side, cov in (("base", cov_base), ("patched", cov_patched)):
            if not cov:
                continue
            changed = e.old_changed if side == "base" else e.new_changed
            for f, lines in cov.items():
                if index.lookup(f, side) is e:
                    inter = sorted(set(lines) & changed)
                    if inter:
                        hit[side][e.diff.path] = inter[:20]
    if not (hit["base"] or hit["patched"]):
        return {"type": "execution_path", "level": "unknown", "note": "run executed no changed lines"}
    return {"type": "execution_path", "level": "execution_path" if outcome_differs else "near_line",
            "executed_changed_lines": hit, "outcome_differs": outcome_differs}


def summarize_correlation(evidence: list[dict]) -> dict:
    ev = [e for e in evidence if e]
    if not ev:
        return {"level": "unknown", "relation": "unknown", "evidence": [],
                "note": "insufficient evidence to relate this result to the patch"}
    ev.sort(key=lambda e: (RANK[e["level"]], e.get("stack_depth", 0)))
    top = ev[0]["level"]
    rel = "linked" if top in LINKED else ("weak" if top in ("near_line", "changed_file") else "unknown")
    out = {"level": top, "relation": rel, "evidence": ev}
    if rel == "weak":
        out["note"] = "adjacency / same-file only: not sufficient to claim the patch caused or fixed this"
    return out
