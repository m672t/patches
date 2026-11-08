"""Unified-diff parsing + tree diffing (no git required for directory sources)."""
from __future__ import annotations

import difflib
import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@ ?(.*)$")
DEFAULT_EXCLUDE = [".git/*", "*.o", "*.a", "*.so", "*.gcda", "*.gcno", "*.d"]


@dataclass
class Hunk:
    old_start: int
    old_len: int
    new_start: int
    new_len: int
    section: str = ""
    removed: list[int] = field(default_factory=list)      # old-side line numbers
    added: list[int] = field(default_factory=list)        # new-side line numbers
    old_anchors: list[int] = field(default_factory=list)  # old line where a change block sits
    new_anchors: list[int] = field(default_factory=list)


@dataclass
class FileDiff:
    old_path: str | None = None
    new_path: str | None = None
    status: str = "modified"
    binary: bool = False
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or ""


def _clean_path(p: str) -> str | None:
    p = p.split("\t")[0].strip().strip('"')
    if p == "/dev/null":
        return None
    if p.startswith(("a/", "b/")):
        p = p[2:]
    return p


def parse_unified_diff(text: str) -> list[FileDiff]:
    lines = text.splitlines()
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    seen_minus = False
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if line.startswith("diff --git "):
            cur = FileDiff()
            files.append(cur)
            seen_minus = False
            m = re.match(r"^diff --git a/(.*?) b/(.*)$", line)
            if m:
                cur.old_path, cur.new_path = m.group(1), m.group(2)
        elif line.startswith("--- ") and i + 1 < n and lines[i + 1].startswith("+++ "):
            if cur is None or cur.hunks or seen_minus:
                cur = FileDiff()
                files.append(cur)
            seen_minus = True
            cur.old_path = _clean_path(line[4:])
            cur.new_path = _clean_path(lines[i + 1][4:])
            if cur.old_path is None:
                cur.status = "added"
            if cur.new_path is None:
                cur.status = "deleted"
            i += 1
        elif cur is not None and line.startswith("new file mode"):
            cur.status = "added"
        elif cur is not None and line.startswith("deleted file mode"):
            cur.status = "deleted"
        elif cur is not None and line.startswith("rename from "):
            cur.status = "renamed"
            cur.old_path = line[len("rename from "):]
        elif cur is not None and line.startswith("rename to "):
            cur.new_path = line[len("rename to "):]
        elif cur is not None and (line.startswith("Binary files") or line.startswith("GIT binary patch")):
            cur.binary = True
        elif cur is not None and line.startswith("@@"):
            m = HUNK_RE.match(line)
            if not m:
                i += 1
                continue
            os_, ol, ns, nl = int(m.group(1)), m.group(2), int(m.group(3)), m.group(4)
            h = Hunk(os_, 1 if ol is None else int(ol), ns, 1 if nl is None else int(nl), m.group(5).strip())
            old_ln, new_ln = os_, ns
            rem_old, rem_new = h.old_len, h.new_len
            in_block = False
            i += 1
            while i < n and (rem_old > 0 or rem_new > 0 or (lines[i].startswith("\\"))):
                b = lines[i]
                tag = b[:1]
                if tag == "\\":
                    i += 1
                    continue
                if tag == "-":
                    if not in_block:
                        h.old_anchors.append(old_ln)
                        h.new_anchors.append(new_ln)
                        in_block = True
                    h.removed.append(old_ln)
                    old_ln += 1
                    rem_old -= 1
                elif tag == "+":
                    if not in_block:
                        h.old_anchors.append(old_ln)
                        h.new_anchors.append(new_ln)
                        in_block = True
                    h.added.append(new_ln)
                    new_ln += 1
                    rem_new -= 1
                else:  # context (' ' or empty)
                    in_block = False
                    old_ln += 1
                    new_ln += 1
                    rem_old -= 1
                    rem_new -= 1
                i += 1
            cur.hunks.append(h)
            continue
        i += 1
    return files


def _excluded(rel: str, patterns) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(Path(rel).name, p) for p in patterns)


def _read_text(p: Path):
    data = p.read_bytes()
    if b"\0" in data[:8000]:
        return None
    return data.decode("utf-8", errors="replace").splitlines()


def make_tree_diff(base_dir: Path, patched_dir: Path, exclude=None) -> str:
    """git-style unified diff between two source trees."""
    exclude = list(exclude or DEFAULT_EXCLUDE)

    def listing(root: Path):
        return {
            p.relative_to(root).as_posix()
            for p in root.rglob("*")
            if p.is_file() and not _excluded(p.relative_to(root).as_posix(), exclude)
        }

    out: list[str] = []
    for rel in sorted(listing(base_dir) | listing(patched_dir)):
        a, b = base_dir / rel, patched_dir / rel
        a_lines = _read_text(a) if a.is_file() else []
        b_lines = _read_text(b) if b.is_file() else []
        if (a.is_file() and a_lines is None) or (b.is_file() and b_lines is None):
            if a.is_file() != b.is_file() or a.read_bytes() != b.read_bytes():
                out.append(f"diff --git a/{rel} b/{rel}\nBinary files a/{rel} and b/{rel} differ")
            continue
        if a_lines == b_lines and a.is_file() == b.is_file():
            continue
        out.append(f"diff --git a/{rel} b/{rel}")
        if not a.is_file():
            out.append("new file mode 100644")
        if not b.is_file():
            out.append("deleted file mode 100644")
        out.extend(
            difflib.unified_diff(
                a_lines, b_lines,
                "/dev/null" if not a.is_file() else f"a/{rel}",
                "/dev/null" if not b.is_file() else f"b/{rel}",
                n=3, lineterm="",
            )
        )
    return "\n".join(out) + ("\n" if out else "")
