"""Command-line runner for the starter package."""

from __future__ import annotations

import json
import sys

from sandbox_starter.business_logic import execute
from sandbox_starter.config import StarterConfig
from sandbox_starter.metrics import write_metrics
from sandbox_starter.models import BusinessResult


def write_output(result: BusinessResult, config: StarterConfig) -> None:
    """Write optional JSON output for downstream tools."""

    if config.output_path is None:
        return

    config.output_path.parent.mkdir(parents=True, exist_ok=True)
    config.output_path.write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    """Run the starter workflow."""

    config = StarterConfig.from_env()
    result = execute(config)
    write_metrics(config, result)
    write_output(result, config)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
