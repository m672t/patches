"""
PatchGuard - Person 2 plugin
Dynamic boundary/input generation and stronger runtime error classification.

This plugin intentionally does NOT implement reproducer bundles, minimization,
hardening checks, CI configuration, or container isolation (those belong to
persons 3 and 4).
"""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path


MAX_CASES = 24
MAX_INPUT_BYTES = 4096
BOUNDARY_SIZES = (0, 1, 2, 15, 16, 17, 31, 32, 63, 64, 127, 128, 255, 256, 1024)


def _bytes_from_spec(spec, base_dir: Path) -> bytes | None:
    """Decode the same input forms accepted by PatchGuard's materialize()."""
    if spec is None:
        return None
    if isinstance(spec, str):
        return spec.encode()
    if not isinstance(spec, dict):
        return None
    try:
        if "text" in spec:
            data = str(spec["text"]).encode()
        elif "hex" in spec:
            data = bytes.fromhex(str(spec["hex"]).replace(" ", ""))
        elif "b64" in spec:
            data = base64.b64decode(spec["b64"], validate=True)
        elif "path" in spec:
            data = (base_dir / str(spec["path"])).read_bytes()
        else:
            return None
        data *= max(0, int(spec.get("repeat", 1)))
        return (str(spec.get("prefix", "")).encode() + data
                + str(spec.get("suffix", "")).encode())
    except (OSError, ValueError, TypeError):
        return None


def _hex_spec(data: bytes) -> dict:
    return {"hex": data.hex()}


def _safe_id(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return value[:48] or "case"


def _clone_for_check(seed: dict, test_id: str, category: str, description: str) -> dict:
    """Keep transport settings, but never inherit an unrelated oracle."""
    t = dict(seed)
    t["id"] = test_id
    t["category"] = category
    t["role"] = "check"
    t["description"] = description
    t["expect"] = {}       # no guessed oracle: generated input is exploratory
    t.setdefault("args", [])
    t.setdefault("env", {})
    return t


def provide_tests(ctx) -> list[dict]:
    """
    Generate deterministic boundary/invalid cases from configured test seeds.

    Important: pipeline.py calls this hook BEFORE assigning ctx.tests. Therefore
    read the normalized configuration through ctx.cfg["tests"], not ctx.tests.
    """
    cfg = ctx.cfg
    seeds = list(cfg.get("tests", []) or [])
    base_dir = Path(getattr(cfg, "base_dir", "."))
    generated: list[dict] = []
    seen: set[str] = set()

    def add(test: dict):
        if len(generated) >= MAX_CASES:
            return
        # Stable ID and content-based de-duplication.
        tid = _safe_id(test["id"])
        test["id"] = tid
        fingerprint = repr(sorted((k, repr(v)) for k, v in test.items()))
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        generated.append(test)

    # If a target config has no input seed, still exercise common stdin sizes.
    if not seeds:
        for n in (0, 1, 16, 64, 256):
            add({
                "id": f"p2_stdin_len_{n}",
                "category": "boundary" if n else "invalid",
                "role": "check",
                "description": f"generated stdin probe ({n} bytes); exploratory only",
                "stdin": _hex_spec(b"A" * n),
                "args": [], "env": {}, "expect": {},
            })
        return generated

    transport_counts = {
       "stdin": 0,
       "args": 0,
       "files": 0,
    }
    transport_limits = {
       "stdin": 12,
       "args": 6,
       "files": 6,
    }
    for seed_index, seed in enumerate(seeds):
        if len(generated) >= MAX_CASES:
            break
        seed_id = _safe_id(str(seed.get("id", f"seed{seed_index}")))

        # 1) stdin boundary probes, derived from the configured seed.
        if "stdin" in seed:
            original = _bytes_from_spec(seed.get("stdin"), base_dir)
            if original is not None:
                candidates = [
                    ("empty", b"", "invalid"),
                    ("one_byte", original[:1], "boundary"),
                    ("minus_one", original[:-1], "boundary"),
                    ("plus_nul", original + b"\x00", "boundary"),
                    ("plus_byte", original + b"A", "boundary"),
                    ("doubled", original * 2, "boundary"),
                ]
                # Add canonical size probes without exploding the test matrix.
                for n in BOUNDARY_SIZES:
                    if n in (len(original), len(original) - 1, len(original) + 1):
                        continue
                    candidates.append((f"len_{n}", b"A" * n, "boundary"))
                for label, payload, category in candidates:
                    if len(payload) > MAX_INPUT_BYTES:
                        continue
                    t = _clone_for_check(
                        seed, f"p2_{seed_id}_stdin_{label}", category,
                        f"generated {label} stdin probe from {seed_id}; no oracle inferred",
                    )
                    t["stdin"] = _hex_spec(payload)
                    add(t)
                    if len(generated) >= MAX_CASES:
                        break

        # 2) Argument probes: replace each non-option positional argument with
        # empty/short/long values. Keep the rest of the command unchanged.
        args = list(seed.get("args") or [])
        positional = [i for i, a in enumerate(args) if not str(a).startswith("-")
                      and not re.fullmatch(r"\{file:[^}]+\}", str(a))]
        for index in positional[:2]:
            for label, value in (("empty", ""), ("one", "A"),
                                 ("long64", "A" * 64), ("long256", "A" * 256)):
                mutated = list(args)
                mutated[index] = value
                t = _clone_for_check(
                    seed, f"p2_{seed_id}_arg{index}_{label}", "boundary",
                    f"generated argv {label} probe from {seed_id}; no oracle inferred",
                )
                t["args"] = mutated
                add(t)
                if len(generated) >= MAX_CASES:
                    break
            if len(generated) >= MAX_CASES:
                break

        # 3) File probes: retain file names (so {file:name} arguments still work)
        # while exercising empty, truncated, and extended file contents.
        files = seed.get("files") or {}
        for filename, spec in list(files.items())[:2]:
            original = _bytes_from_spec(spec, base_dir)
            if original is None:
                continue
            candidates = [
                ("empty", b"", "invalid"),
                ("first_byte", original[:1], "boundary"),
                ("truncated", original[:-1], "boundary"),
                ("nul_suffix", original + b"\x00", "boundary"),
                ("extended", original + b"A", "boundary"),
            ]
            for label, payload, category in candidates:
                if len(payload) > MAX_INPUT_BYTES:
                    continue
                t = _clone_for_check(
                    seed, f"p2_{seed_id}_file_{_safe_id(filename)}_{label}", category,
                    f"generated file {label} probe for {filename}; no oracle inferred",
                )
                new_files = dict(files)
                new_files[filename] = _hex_spec(payload)
                t["files"] = new_files
                add(t)
                if len(generated) >= MAX_CASES:
                    break
            if len(generated) >= MAX_CASES:
                break

    return generated[:MAX_CASES]


# Canonicalization is deliberately conservative: only explicit runtime
# diagnostics are promoted to confirmed findings. A bare SIGSEGV is not.
_ASAN_TYPES = (
    ("heap-buffer-overflow", "heap-buffer-overflow"),
    ("stack-buffer-overflow", "stack-buffer-overflow"),
    ("global-buffer-overflow", "global-buffer-overflow"),
    ("heap-use-after-free", "use-after-free"),
    ("stack-use-after-return", "stack-use-after-return"),
    ("stack-use-after-scope", "stack-use-after-scope"),
    ("use-after-poison", "use-after-poison"),
    ("double-free", "double-free"),
    ("attempting free on address which was not malloc()-ed", "invalid-free"),
    ("alloc-dealloc-mismatch", "alloc-dealloc-mismatch"),
    (" odr-violation", "odr-violation"),
    ("container-overflow", "container-overflow"),
    ("negative-size-param", "negative-size"),
    ("memcpy-param-overlap", "overlapping-memory-copy"),
    ("allocation-size-too-big", "allocation-size-overflow"),
    ("stack-overflow", "stack-overflow"),
    ("SEGV", "segv"),
    ("FPE", "arithmetic-exception"),
)

_UBSAN_TYPES = (
    ("signed integer overflow", "signed-integer-overflow"),
    ("unsigned integer overflow", "unsigned-integer-overflow"),
    ("division by zero", "divide-by-zero"),
    ("shift exponent", "invalid-shift"),
    ("out of bounds", "array-index-out-of-bounds"),
    ("index ", "array-index-out-of-bounds"),
    ("null pointer", "null-pointer-dereference"),
    ("misaligned address", "misaligned-access"),
    ("pointer overflow", "pointer-overflow"),
    ("object-size", "object-size-violation"),
    ("vptr", "invalid-vptr"),
)

_GLIBC_TYPES = (
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
    ("corrupted double-linked list", "heap-corruption", "glibc_abort"),
    ("free(): invalid next size", "heap-corruption", "glibc_abort"),
)


def classify_run(obs: dict, ctx) -> dict | None:
    """
    Strengthen the core observation using explicit ASan/UBSan/glibc diagnostics.

    Return only observation fields consumed by runner/analyzer. In particular,
    never confirm an unclassified signal merely because it is SIGSEGV/SIGABRT.
    """
    stderr = str(obs.get("stderr") or "")
    lower = stderr.lower()
    result: dict = {}

    # Address/Leak/Memory/Thread Sanitizer reports.
    san = re.search(
        r"ERROR:\s*(AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer):\s*([^\s]+)",
        stderr, re.I,
    )
    if san:
        sanitizer = san.group(1).lower()
        raw_type = san.group(2).lower()
        if sanitizer == "leaksanitizer":
            error_type, mechanism = "memory-leak", "sanitizer:lsan"
        elif sanitizer == "addresssanitizer":
            error_type = next((mapped for token, mapped in _ASAN_TYPES if token in raw_type),
                              raw_type.replace("_", "-"))
            mechanism = "sanitizer:asan"
        elif sanitizer == "memorysanitizer":
            error_type, mechanism = "uninitialized-memory-use", "sanitizer:msan"
        else:
            error_type, mechanism = "data-race-or-thread-error", "sanitizer:tsan"
        result.update(crash=True, error_type=error_type, mechanism=mechanism, confirmed=True)

    # UBSan's "runtime error" lines are explicit even when process does not abort.
    if not result:
        ub = re.search(r"runtime error:\s*(.+)", stderr, re.I)
        if ub:
            msg = ub.group(1).strip().lower()
            error_type = next((mapped for token, mapped in _UBSAN_TYPES if token in msg),
                              "undefined-behavior")
            result.update(crash=True, error_type=error_type,
                          mechanism="sanitizer:ubsan", confirmed=True)

    # Hardened libc / stack protector diagnostics.
    if not result:
        for needle, error_type, mechanism in _GLIBC_TYPES:
            if needle.lower() in lower:
                result.update(crash=True, error_type=error_type,
                              mechanism=mechanism, confirmed=True)
                break

    # Do not upgrade an unexplained signal. The core's expect.signal contract
    # remains the only signal-only confirmation mechanism.
    if result:
        # Preserve stack data already parsed by observation.py.
        for key in ("frames", "app_frames", "top_function", "top_file", "top_line"):
            if key in obs:
                result[key] = obs[key]
        return result
    return None
