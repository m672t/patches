# PatchGuard - Person 2 handoff

## Files
- `plugins/person2.py`: `provide_tests(ctx)` and `classify_run(obs, ctx)`.
- `tests/test_person2.py`: focused unit tests for this plugin.

## Connect it
Add this entry to the target config's `plugins` array:

```json
"plugins": ["plugins/person2.py"]
```

The path is relative to the config file directory. If the config is in
`examples/demo/`, place/copy the plugin at `examples/demo/plugins/person2.py`
or use the correct relative path to the shared plugin file.

## Scope and design
- The plugin creates deterministic exploratory probes from configured stdin,
  argv and file seeds; at most 24 extra tests.
- Generated probes use `role: check` and an empty `expect` object. It never
  invents an expected output or labels a generated probe as the known target.
- Explicit ASan, UBSan, glibc, Fortify and stack-canary diagnostics are upgraded
  to confirmed observations.
- A bare signal such as SIGSEGV is never promoted to a confirmed security error.
- Release/sanitized separation, replay stability, functional regression
  comparison, and verdict generation remain in the core.
- Reproducer bundles, minimization, regression-test persistence, ELF hardening,
  CI and container isolation are intentionally out of scope (persons 3/4).

## Run focused tests
From this directory:

```bash
python3 -m unittest discover -s tests -v
```

Then from the PatchGuard repository root:

```bash
python3 -m unittest discover -s tests
bash examples/demo/run_all.sh
```

If the repository's existing test suite is stored elsewhere, keep this focused
test command separate and run the existing suite as documented in the root README.
