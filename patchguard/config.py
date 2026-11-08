"""Config loading + validation. Adding a new target = writing a new config file only."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

CATEGORIES = {"exploit", "functional", "boundary", "invalid"}
ROLES = {"target", "variant", "check"}   # target/variant: expected to crash on the base version

DEFAULT_RUN = {
    "timeout": 5, "repeats": 3, "cpu_seconds": 10, "memory_mb": 1024, "max_output_bytes": 1 << 20,
    "exec_prefix": [], "env": {}, "jobs": 1,
}
DEFAULT_SAN_ENV = {
    "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0:symbolize=1:color=never:allocator_may_return_null=0",
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:color=never",
}


class ConfigError(Exception):
    pass


@dataclass
class Config:
    raw: dict
    path: Path | None
    base_dir: Path
    errors: list[str] = field(default_factory=list)

    def __getitem__(self, k):
        return self.raw[k]

    def get(self, k, d=None):
        return self.raw.get(k, d)


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}")
    except json.JSONDecodeError as e:
        raise ConfigError(f"invalid JSON in {path}: {e}")


def load_config(path: str | Path, overrides: dict | None = None) -> Config:
    path = Path(path).resolve()
    raw = _load_json(path)
    base_dir = path.parent
    cfg = Config(raw=raw, path=path, base_dir=base_dir)
    apply_overrides(cfg, overrides or {})
    normalise(cfg)
    validate(cfg)
    return cfg


def apply_overrides(cfg: Config, ov: dict):
    """CLI overrides (used on defense day to feed unseen patches without editing the config)."""
    v = cfg.raw.setdefault("versions", {"base": {}, "patched": {}})
    for side, key in (("base", "base_path"), ("patched", "patched_path")):
        if ov.get(key):
            v[side] = {"path": ov[key]}
    for side, key in (("base", "base_rev"), ("patched", "patched_rev")):
        if ov.get(key):
            v.setdefault(side, {})
            git = dict(v[side].get("git") or {})
            git["rev"] = ov[key]
            if ov.get("repo"):
                git["repo"] = ov["repo"]
            v[side] = {"git": git}
    if ov.get("patch_file"):
        cfg.raw.setdefault("diff", {})["file"] = ov["patch_file"]
    if ov.get("workdir"):
        cfg.raw["workdir"] = ov["workdir"]
    if ov.get("repeats"):
        cfg.raw.setdefault("run", {})["repeats"] = ov["repeats"]
    if ov.get("jobs"):
        cfg.raw.setdefault("run", {})["jobs"] = ov["jobs"]


def normalise(cfg: Config):
    r = cfg.raw
    r.setdefault("name", cfg.path.stem if cfg.path else "target")
    r.setdefault("workdir", ".patchguard")
    r["run"] = {**DEFAULT_RUN, **(r.get("run") or {})}
    r.setdefault("build", {}).setdefault("timeout", 600)
    r.setdefault("diff", {})
    r.setdefault("plugins", [])
    r.setdefault("output", {})
    tests = list(r.get("tests") or [])
    if r.get("tests_file"):
        extra = _load_json(cfg.base_dir / r["tests_file"])
        tests += extra["tests"] if isinstance(extra, dict) else extra
    r["tests"] = tests
    for t in tests:
        t.setdefault("category", "functional")
        t.setdefault("role", "target" if t["category"] == "exploit" else "check")
        t.setdefault("args", [])
        t.setdefault("env", {})
        t.setdefault("expect", {})


def validate(cfg: Config):
    e = cfg.errors
    r = cfg.raw
    vers = r.get("versions") or {}
    for side in ("base", "patched"):
        v = vers.get(side)
        if not v or not (v.get("path") or (v.get("git") or {}).get("rev")):
            e.append(f"versions.{side}: need 'path' or 'git.rev'")
    modes = (r.get("build") or {}).get("modes") or {}
    if "release" not in modes:
        e.append("build.modes.release is required (the shipped-binary build)")
    for name, m in modes.items():
        for k in ("cmd", "binary"):
            if not m.get(k):
                e.append(f"build.modes.{name}.{k} is missing")
    seen = set()
    for i, t in enumerate(r["tests"]):
        tid = t.get("id")
        if not tid:
            e.append(f"tests[{i}]: missing 'id'")
            continue
        if tid in seen:
            e.append(f"duplicate test id {tid}")
        seen.add(tid)
        if t["category"] not in CATEGORIES:
            e.append(f"test {tid}: category must be one of {sorted(CATEGORIES)}")
        if t["role"] not in ROLES:
            e.append(f"test {tid}: role must be one of {sorted(ROLES)}")
    if not any(t.get("role") in ("target", "variant") for t in r["tests"]):
        e.append("at least one test with role 'target' (the known bug trigger) is required")
    if (vers.get("base") or {}).get("git") and (vers.get("patched") or {}).get("git"):
        pass
