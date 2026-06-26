"""PEP 517 backend wrapper for sandbox install-time metrics.

The sandbox runs `uv pip install --python <venv>/bin/python -e .` during repo
bootstrap. This backend records the same package-load metrics during that
editable install, then delegates all packaging behavior to setuptools.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from setuptools import build_meta as _setuptools


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"


def _write_install_load_metrics() -> None:
    """Write the same load metrics used by `import sandbox_starter`."""

    sys.path.insert(0, str(SRC_DIR))
    try:
        from sandbox_starter.metrics import write_load_metrics_from_env

        write_load_metrics_from_env(
            trigger="uv pip install -e .",
            health_label="Editable package install",
        )
    finally:
        try:
            sys.path.remove(str(SRC_DIR))
        except ValueError:
            pass


def build_editable(
    wheel_directory: str,
    config_settings: dict[str, Any] | None = None,
    metadata_directory: str | None = None,
) -> str:
    """Build an editable wheel after recording install-time metrics."""

    _write_install_load_metrics()
    return _setuptools.build_editable(
        wheel_directory,
        config_settings=config_settings,
        metadata_directory=metadata_directory,
    )


def build_wheel(
    wheel_directory: str,
    config_settings: dict[str, Any] | None = None,
    metadata_directory: str | None = None,
) -> str:
    """Build a wheel after recording install-time metrics."""

    _write_install_load_metrics()
    return _setuptools.build_wheel(
        wheel_directory,
        config_settings=config_settings,
        metadata_directory=metadata_directory,
    )


def prepare_metadata_for_build_editable(
    metadata_directory: str,
    config_settings: dict[str, Any] | None = None,
) -> str:
    return _setuptools.prepare_metadata_for_build_editable(
        metadata_directory,
        config_settings=config_settings,
    )


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: dict[str, Any] | None = None,
) -> str:
    return _setuptools.prepare_metadata_for_build_wheel(
        metadata_directory,
        config_settings=config_settings,
    )


def get_requires_for_build_editable(
    config_settings: dict[str, Any] | None = None,
) -> list[str]:
    return _setuptools.get_requires_for_build_editable(
        config_settings=config_settings,
    )


def get_requires_for_build_wheel(
    config_settings: dict[str, Any] | None = None,
) -> list[str]:
    return _setuptools.get_requires_for_build_wheel(
        config_settings=config_settings,
    )
