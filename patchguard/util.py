"""Small shared helpers (no project logic)."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path


def sha256_file(path: str | os.PathLike) -> str | None:
    p = Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_tree(root: str | os.PathLike, exclude=(".git",)) -> str:
    """Deterministic digest of a directory tree (used as version id when no git)."""
    h = hashlib.sha256()
    root = Path(root)
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in exclude for part in rel.parts) or not p.is_file():
            continue
        h.update(str(rel).encode())
        h.update(b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def materialize(spec, base_dir: Path) -> bytes:
    """Turn a data spec into bytes.

    spec: str (plain text) | {"text"|"hex"|"b64"|"path": ..., "repeat": N,
                              "prefix": str, "suffix": str}
    """
    if spec is None:
        return b""
    if isinstance(spec, str):
        return spec.encode()
    if "text" in spec:
        data = spec["text"].encode()
    elif "hex" in spec:
        data = bytes.fromhex(spec["hex"].replace(" ", ""))
    elif "b64" in spec:
        data = base64.b64decode(spec["b64"])
    elif "path" in spec:
        data = (base_dir / spec["path"]).read_bytes()
    else:
        raise ValueError(f"bad data spec: {spec!r}")
    data = data * int(spec.get("repeat", 1))
    return spec.get("prefix", "").encode() + data + spec.get("suffix", "").encode()


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
