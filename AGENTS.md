# Sandbox Starter Package

This repository is designed to be cloned directly by the Sandbox Agent. The
sandbox init script will detect `pyproject.toml`, create `.venv`, and install
the package in editable mode.

The editable install runs a local PEP 517 backend wrapper that writes first-load
health metrics before delegating to `setuptools.build_meta`.

## Commands

Use absolute venv paths. Do not run `source .venv/bin/activate`.

```bash
/workspace/my-starter-pack/.venv/bin/python -c "import sandbox_starter"
/workspace/my-starter-pack/.venv/bin/starter-run
/workspace/my-starter-pack/.venv/bin/python -m sandbox_starter
/workspace/my-starter-pack/.venv/bin/python -m unittest discover -s tests
```

If the clone path differs, replace `/workspace/my-starter-pack` with the
actual repo path shown in `/workspace/AGENTS.md`.

## Business Logic

Developers should put business logic in:

```text
src/sandbox_starter/business_logic.py
```

The stable entrypoint is:

```python
execute(config: StarterConfig) -> BusinessResult
```

Keep orchestration, environment parsing, and output writing in `runner.py`.
Keep domain-specific work in `business_logic.py`.

## Configuration

The default runner reads:

- `STARTER_INPUT_TEXT`: text input for the starter job.
- `STARTER_OUTPUT_PATH`: optional JSON output path.
- `STARTER_METRICS_PATH`: optional markdown metrics output path. Defaults to
  `/workspace/.artifacts/starter-metrics.md` in a sandbox.
- `STARTER_LOAD_METRICS_PATH`: optional package-load metrics output path.
  Defaults to `/workspace/.artifacts/starter-load-metrics.md` in a sandbox.
- `STARTER_DISABLE_LOAD_METRICS=1`: disables install/import-time load metrics.

When adding new configuration, update `StarterConfig.from_env()` in
`src/sandbox_starter/config.py`.

## Metrics Artifact

Every `starter-run` execution writes metrics markdown for the agent to inspect:

```text
/workspace/.artifacts/starter-metrics.md
```

The editable install and first package load write health metrics:

```text
/workspace/.artifacts/starter-load-metrics.md
```

The metrics include business analytics and safe runtime diagnostics. Do not add
environment-variable dumps to these files.
