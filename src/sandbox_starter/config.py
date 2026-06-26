"""Configuration loading for the starter runner."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path


def default_metrics_path() -> Path:
    """Return the default metrics path for sandbox and local runs."""

    if Path("/workspace").exists():
        return Path("/workspace/.artifacts/starter-metrics.md")
    return Path.cwd() / "output" / "starter-metrics.md"


@dataclass(frozen=True)
class StarterConfig:
    """Runtime configuration for the starter business logic."""

    input_text: str
    output_path: Path | None = None
    metrics_path: Path = field(default_factory=default_metrics_path)

    @classmethod
    def from_env(cls) -> "StarterConfig":
        """Create configuration from environment variables."""

        output_path_raw = os.environ.get("STARTER_OUTPUT_PATH", "").strip()
        output_path = Path(output_path_raw) if output_path_raw else None
        metrics_path_raw = os.environ.get("STARTER_METRICS_PATH", "").strip()
        metrics_path = Path(metrics_path_raw) if metrics_path_raw else default_metrics_path()

        return cls(
            input_text=os.environ.get(
                "STARTER_INPUT_TEXT",
                "Hello from the Sandbox Agent starter package.",
            ),
            output_path=output_path,
            metrics_path=metrics_path,
        )
