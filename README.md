# Sandbox Starter Package

Starter Python package for Sandbox Agent jobs. It is ready to be cloned as the
repository attached to a sandbox preset/config.

When the sandbox starts, the existing sandbox bootstrap will:

1. Clone this repository into `/workspace/my-starter-pack`.
2. Detect `pyproject.toml`.
3. Create `.venv`.
4. Install this package in editable mode.

Install does not run business logic. The first automatic health metrics check
runs during editable package install and again when Python loads the package.
During sandbox bootstrap, this command is run by existing sandbox init:

```bash
uv pip install --python /workspace/my-starter-pack/.venv/bin/python -e .
```

That install writes:

```text
/workspace/.artifacts/starter-load-metrics.md
```

The same metrics writer also runs when the package is imported, for example:

```bash
/workspace/my-starter-pack/.venv/bin/python -c "import sandbox_starter"
```

Inside a sandbox, that import writes to the same path:

```text
/workspace/.artifacts/starter-load-metrics.md
```

## Run

```bash
/workspace/my-starter-pack/.venv/bin/starter-run
```

Equivalent module entrypoint:

```bash
/workspace/my-starter-pack/.venv/bin/python -m sandbox_starter
```

## Configure

```bash
STARTER_INPUT_TEXT="Hello from the sandbox" \
STARTER_OUTPUT_PATH="/workspace/my-starter-pack/output/result.json" \
/workspace/my-starter-pack/.venv/bin/starter-run
```

The runner also writes safe business/runtime metrics to:

```text
/workspace/.artifacts/starter-metrics.md
```

Override the metrics location with:

```bash
STARTER_METRICS_PATH="/workspace/my-starter-pack/output/metrics.md" \
/workspace/my-starter-pack/.venv/bin/starter-run
```

Override the package-load metrics path with:

```bash
STARTER_LOAD_METRICS_PATH="/workspace/my-starter-pack/output/load-metrics.md" \
/workspace/my-starter-pack/.venv/bin/python -c "import sandbox_starter"
```

## Test

```bash
/workspace/my-starter-pack/.venv/bin/python -m unittest discover -s tests
```

## Where To Add Business Logic

Edit:

```text
src/sandbox_starter/business_logic.py
```

The runner calls:

```python
execute(config: StarterConfig) -> BusinessResult
```

Add dependencies in `pyproject.toml` under `[project].dependencies`.

## Metrics

The default workflow demonstrates actionable metrics:

- Input normalization.
- Word count.
- Unique word count.
- Character count.
- Average word length.
- Longest word.
- Safe runtime diagnostics.

Metrics intentionally do not dump environment variables because sandbox env may
contain credentials.

There are two metrics files:

- `/workspace/.artifacts/starter-load-metrics.md`: created during editable
  install and on package import.
- `/workspace/.artifacts/starter-metrics.md`: created by `starter-run`.
