"""Heuristic C/C++ function-range finder (so a changed line maps to a function)."""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

KEYWORDS = {
    "if", "while", "for", "switch", "catch", "sizeof", "return", "__attribute__",
    "alignas", "decltype", "noexcept", "else", "do", "static_assert", "defined",
}
_NAME_RE = re.compile(
    r"((?:[A-Za-z_]\w*(?:<[^<>]*>)?\s*::\s*)*(?:~?[A-Za-z_]\w*|operator\s*(?:\(\s*\)|[^\s\w(]+)))\s*\("
)
_CTX_RE = re.compile(r"^\s*(?:typedef\s+)?(namespace|class|struct|union)\b|^\s*extern\b")


@dataclass
class Func:
    name: str
    start: int
    end: int


def norm_func(name: str | None) -> str | None:
    """Normalise a (possibly demangled) function name for comparison."""
    if not name:
        return None
    n = name
    while True:
        n2 = re.sub(r"<[^<>]*>", "", n)
        if n2 == n:
            break
        n = n2
    if "operator" not in n:
        n = n.split("(")[0]
    n = n.strip().split("::")[-1].strip()
    return n or None


def mask_source(src: str) -> str:
    """Blank out comments, string/char literals and preprocessor lines (keep newlines)."""
    out: list[str] = []
    i, n = 0, len(src)
    blank = lambda s: re.sub(r"[^\n]", " ", s)  # noqa: E731
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(blank(src[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(blank(src[i:j]))
            i = j
        elif c == "#" and src[src.rfind("\n", 0, i) + 1:i].strip() == "":
            j = i
            while j < n:
                e = src.find("\n", j)
                if e == -1:
                    j = n
                    break
                if src[e - 1] == "\\":
                    j = e + 1
                    continue
                j = e
                break
            out.append(blank(src[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _classify(header: str):
    h = header.strip()
    if not h or re.match(r"^(typedef\s+)?enum\b", h):
        return "other", None, 0
    paren = h.find("(")
    eq = h.find("=")
    if paren != -1 and (eq == -1 or eq > paren):
        for m in _NAME_RE.finditer(header):
            last = m.group(1).split("::")[-1].strip()
            if last not in KEYWORDS:
                return "func", re.sub(r"\s+", "", m.group(1)), m.start(1)
        return "other", None, 0
    if eq != -1:
        return "other", None, 0
    if _CTX_RE.match(h):
        return "ctx", None, 0
    return "other", None, 0


def find_functions(src: str) -> list[Func]:
    m = mask_source(src)
    nl = [i for i, ch in enumerate(m) if ch == "\n"]
    line_of = lambda off: bisect.bisect_right(nl, off - 1) + 1 if off > 0 else 1  # noqa: E731
    funcs: list[Func] = []
    stack: list[tuple] = []
    seg = 0
    for i, c in enumerate(m):
        if c == ";":
            if not any(s[0] == "func" for s in stack):
                seg = i + 1
        elif c == "{":
            if any(s[0] == "func" for s in stack):
                stack.append(("other",))
            else:
                kind, name, noff = _classify(m[seg:i])
                stack.append((kind, name, seg + noff))
                if kind == "ctx":
                    seg = i + 1
        elif c == "}":
            ent = stack.pop() if stack else None
            if ent and ent[0] == "func":
                funcs.append(Func(ent[1], line_of(ent[2]), line_of(i)))
            if not any(s[0] == "func" for s in stack):
                seg = i + 1
    return funcs


def enclosing(funcs: list[Func], line: int) -> Func | None:
    best = None
    for f in funcs:
        if f.start <= line <= f.end and (best is None or (f.end - f.start) < (best.end - best.start)):
            best = f
    return best
