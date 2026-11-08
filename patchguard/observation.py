"""Turn a raw process result into a structured observation (crash / type / mechanism / frames).

This is the *minimal* classifier the core needs. Person 2 extends or replaces it through the
`classify_run(obs, ctx)` plugin hook (see plugins.py) without touching the core.
"""
from __future__ import annotations

import re

CRASH_SIGNALS = {"SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL", "SIGTRAP"}

SAN_HEADER = re.compile(
    r"==\d+==ERROR: (AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer): (\S+)(.*)")
UBSAN_RE = re.compile(r"^(?P<file>[^\s:][^:]*):(?P<line>\d+):(?P<col>\d+): runtime error: (?P<msg>.*)$", re.M)
FRAME_RE = re.compile(r"^\s*#(?P<n>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>.+?)\s+(?P<file>[^\s()]+?):(?P<line>\d+)(?::\d+)?\s*$")
FRAME_NOSRC_RE = re.compile(r"^\s*#(?P<n>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>\S.*?)\s+\(.*\+0x[0-9a-fA-F]+\)\s*$")

GLIBC_MESSAGES = [
    ("*** stack smashing detected ***", "stack-buffer-overflow", "canary:__stack_chk_fail"),
    ("*** buffer overflow detected ***", "buffer-overflow", "fortify:__chk_fail"),
    ("double free or corruption", "double-free", "glibc_abort"),
    ("free(): double free detected", "double-free", "glibc_abort"),
    ("free(): invalid pointer", "invalid-free", "glibc_abort"),
    ("free(): invalid size", "invalid-free", "glibc_abort"),
    ("munmap_chunk(): invalid pointer", "invalid-free", "glibc_abort"),
    ("realloc(): invalid pointer", "invalid-free", "glibc_abort"),
    ("corrupted size vs. prev_size", "heap-corruption", "glibc_abort"),
    ("malloc(): corrupted top size", "heap-corruption", "glibc_abort"),
    ("malloc(): invalid size", "heap-corruption", "glibc_abort"),
    ("malloc_consolidate(): invalid chunk size", "heap-corruption", "glibc_abort"),
]

UBSAN_TYPES = [
    ("division by zero", "divide-by-zero"),
    ("signed integer overflow", "signed-integer-overflow"),
    ("out of bounds", "array-index-out-of-bounds"),
    ("null pointer", "null-pointer-dereference"),
    ("shift exponent", "invalid-shift"),
    ("misaligned", "misaligned-access"),
]


def parse_frames(stderr: str) -> list[dict]:
    frames = []
    for line in stderr.splitlines():
        m = FRAME_RE.match(line)
        if m:
            frames.append({"index": int(m["n"]), "function": m["func"], "file": m["file"], "line": int(m["line"])})
            continue
        m = FRAME_NOSRC_RE.match(line)
        if m:
            frames.append({"index": int(m["n"]), "function": m["func"], "file": None, "line": None})
    # keep only the first stack (ASan prints several: access / freed by / allocated by)
    first = []
    for f in frames:
        if first and f["index"] == 0:
            break
        first.append(f)
    return first


def _is_app(frame: dict, build_root: str | None) -> bool:
    path = frame.get("file")
    if not path:
        return False
    if build_root:
        return path.startswith(build_root)
    return not re.search(r"(^/usr/|^/lib/|libsanitizer|sanitizer_common|compiler-rt|^<)", path)


def classify_run(raw: dict, build_root: str | None = None, expect_signal: str | None = None) -> dict:
    """raw: exit_code, signal, timed_out, stdout, stderr  ->  classification dict."""
    stderr = raw.get("stderr", "")
    sig = raw.get("signal")
    res = {"crash": False, "error_type": None, "mechanism": None, "confirmed": False,
           "frames": [], "top_function": None, "top_file": None, "top_line": None}

    if raw.get("timed_out"):
        return res

    m = SAN_HEADER.search(stderr)
    ub = UBSAN_RE.search(stderr)
    if m:
        kind, etype, rest = m.group(1), m.group(2), m.group(3)
        if kind == "LeakSanitizer":
            etype = "memory-leak"
        elif etype == "SEGV":
            addr = re.search(r"address (0x[0-9a-fA-F]+)", rest)
            etype = "null-pointer-dereference" if addr and int(addr[1], 16) < 0x1000 else "segv"
        elif etype == "FPE":
            etype = "arithmetic-exception"
        mech = {"AddressSanitizer": "asan", "LeakSanitizer": "lsan", "MemorySanitizer": "msan",
                "ThreadSanitizer": "tsan"}[kind]
        res.update(crash=True, error_type=etype, mechanism=f"sanitizer:{mech}", confirmed=True)
        res["frames"] = parse_frames(stderr)
    elif ub:
        msg = ub["msg"]
        etype = next((t for k, t in UBSAN_TYPES if k in msg), "ubsan:" + "-".join(msg.split()[:3]))
        res.update(crash=True, error_type=etype, mechanism="sanitizer:ubsan", confirmed=True)
        frames = parse_frames(stderr)
        if not frames:
            frames = [{"index": 0, "function": None, "file": ub["file"], "line": int(ub["line"])}]
        res["frames"] = frames
    else:
        for needle, etype, mech in GLIBC_MESSAGES:
            if needle in stderr:
                res.update(crash=True, error_type=etype, mechanism=mech, confirmed=True)
                break
        else:
            if sig in CRASH_SIGNALS:
                res.update(crash=True, error_type=f"unclassified-{sig.lower()}", mechanism=f"signal:{sig}")
                if expect_signal and expect_signal == sig:
                    res["confirmed"] = True
                    res["mechanism"] = f"signal:{sig}(declared)"
    if res["crash"] and sig and res["mechanism"] and res["mechanism"].startswith(("sanitizer", "canary", "fortify", "glibc")):
        res["signal_seen"] = sig
    app = [f for f in res["frames"] if _is_app(f, build_root)]
    if build_root:
        for f in res["frames"]:
            if f.get("file") and f["file"].startswith(build_root):
                f["file"] = f["file"][len(build_root):].lstrip("/")
    res["app_frames"] = app
    if app:
        res["top_function"], res["top_file"], res["top_line"] = app[0]["function"], app[0]["file"], app[0]["line"]
    return res
