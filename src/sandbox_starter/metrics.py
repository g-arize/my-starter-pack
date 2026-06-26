"""Safe runtime metrics for Sandbox Agent jobs.

This module intentionally does not read or print environment variables because
sandbox env may contain credentials.
"""

from __future__ import annotations

import datetime as dt
import getpass
import os
import platform
import socket
import sys
from pathlib import Path

from sandbox_starter.config import StarterConfig
from sandbox_starter.models import BusinessResult


DEFAULT_LOAD_METRICS_PATH = Path("/workspace/.artifacts/starter-load-metrics.md")


def read_text_if_present(path: Path, max_chars: int = 4000) -> str:
    """Read a small text file for diagnostics, returning a safe placeholder."""

    try:
        value = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "(unavailable)"

    value = value.strip()
    if len(value) > max_chars:
        return value[:max_chars] + "\n...(truncated)"
    return value or "(empty)"


def hostname_ips() -> list[str]:
    """Resolve local hostnames to IPs without failing the run."""

    names = {socket.gethostname(), socket.getfqdn()}
    ips: set[str] = set()
    for name in sorted(n for n in names if n):
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(name, None):
                if family in (socket.AF_INET, socket.AF_INET6):
                    ips.add(str(sockaddr[0]))
        except OSError:
            continue
    return sorted(ips)


def uid_gid() -> str:
    """Return process uid/gid details when available."""

    if not hasattr(os, "getuid"):
        return "(unavailable)"
    return (
        f"uid={os.getuid()} euid={os.geteuid()} "
        f"gid={os.getgid()} egid={os.getegid()}"
    )


def render_metrics_markdown(config: StarterConfig, result: BusinessResult) -> str:
    """Render business and runtime metrics as markdown."""

    now = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
    uname = platform.uname()
    ips = hostname_ips()
    cgroup = read_text_if_present(Path("/proc/self/cgroup"), max_chars=2000)
    namespace = read_text_if_present(
        Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace"),
        max_chars=256,
    )

    lines = [
        "# Starter Package Metrics",
        "",
        f"- Recorded UTC: `{now}`",
        "- Trigger: `starter-run` business workflow",
        "- Environment variables: intentionally not read or printed",
        f"- Metrics path: `{config.metrics_path}`",
        "",
        "## Business Analytics",
        "",
        f"- Input text: `{result.input_text}`",
        f"- Normalized text: `{result.normalized_text}`",
        f"- Word count: `{result.word_count}`",
        f"- Unique word count: `{result.unique_word_count}`",
        f"- Character count: `{result.character_count}`",
        f"- Average word length: `{result.average_word_length}`",
        f"- Longest word: `{result.longest_word or '(none)'}`",
        "",
        "## Process Identity",
        "",
        f"- Whoami: `{getpass.getuser()}`",
        f"- UID/GID: `{uid_gid()}`",
        f"- PID: `{os.getpid()}`",
        f"- Parent PID: `{os.getppid()}`",
        f"- CWD: `{Path.cwd()}`",
        "",
        "## Host Identity",
        "",
        f"- Hostname: `{socket.gethostname()}`",
        f"- FQDN: `{socket.getfqdn()}`",
        f"- Resolved IPs: `{', '.join(ips) if ips else '(none resolved)'}`",
        f"- Kubernetes namespace file: `{namespace}`",
        "",
        "## Runtime",
        "",
        f"- Python executable: `{sys.executable}`",
        f"- Python version: `{sys.version.splitlines()[0]}`",
        f"- Platform: `{platform.platform()}`",
        f"- Machine: `{uname.machine}`",
        f"- Kernel: `{uname.system} {uname.release} {uname.version}`",
        "",
        "## Container Cgroup",
        "",
        "```text",
        cgroup,
        "```",
        "",
    ]
    return "\n".join(lines)


def write_metrics(config: StarterConfig, result: BusinessResult) -> None:
    """Write metrics markdown where the sandbox agent can inspect it."""

    config.metrics_path.parent.mkdir(parents=True, exist_ok=True)
    config.metrics_path.write_text(
        render_metrics_markdown(config, result),
        encoding="utf-8",
    )


def render_load_metrics_markdown(
    metrics_path: Path,
    *,
    trigger: str = "import sandbox_starter",
    health_label: str = "Package import",
) -> str:
    """Render package-load health metrics as markdown."""

    now = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
    uname = platform.uname()
    ips = hostname_ips()
    cgroup = read_text_if_present(Path("/proc/self/cgroup"), max_chars=2000)
    namespace = read_text_if_present(
        Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace"),
        max_chars=256,
    )

    lines = [
        "# Starter Package Load Metrics",
        "",
        f"- Recorded UTC: `{now}`",
        f"- Trigger: `{trigger}` package load",
        "- Environment variables: intentionally not read or printed",
        f"- Metrics path: `{metrics_path}`",
        "",
        "## Health",
        "",
        f"- {health_label}: `ok`",
        f"- Python executable exists: `{Path(sys.executable).exists()}`",
        "",
        "## Process Identity",
        "",
        f"- Whoami: `{getpass.getuser()}`",
        f"- UID/GID: `{uid_gid()}`",
        f"- PID: `{os.getpid()}`",
        f"- Parent PID: `{os.getppid()}`",
        f"- CWD: `{Path.cwd()}`",
        "",
        "## Host Identity",
        "",
        f"- Hostname: `{socket.gethostname()}`",
        f"- FQDN: `{socket.getfqdn()}`",
        f"- Resolved IPs: `{', '.join(ips) if ips else '(none resolved)'}`",
        f"- Kubernetes namespace file: `{namespace}`",
        "",
        "## Runtime",
        "",
        f"- Python executable: `{sys.executable}`",
        f"- Python version: `{sys.version.splitlines()[0]}`",
        f"- Platform: `{platform.platform()}`",
        f"- Machine: `{uname.machine}`",
        f"- Kernel: `{uname.system} {uname.release} {uname.version}`",
        "",
        "## Container Cgroup",
        "",
        "```text",
        cgroup,
        "```",
        "",
    ]
    return "\n".join(lines)


def load_metrics_path_from_env() -> Path | None:
    """Return the load-metrics path, or None when import metrics are disabled."""

    if os.environ.get("STARTER_DISABLE_LOAD_METRICS", "").strip() == "1":
        return None

    override = os.environ.get("STARTER_LOAD_METRICS_PATH", "").strip()
    if override:
        return Path(override)

    if Path("/workspace").exists():
        return DEFAULT_LOAD_METRICS_PATH

    return None


def write_load_metrics_from_env(
    *,
    trigger: str = "import sandbox_starter",
    health_label: str = "Package import",
) -> Path | None:
    """Write package-load metrics when configured for the current environment."""

    metrics_path = load_metrics_path_from_env()
    if metrics_path is None:
        return None

    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(
        render_load_metrics_markdown(
            metrics_path,
            trigger=trigger,
            health_label=health_label,
        ),
        encoding="utf-8",
    )
    return metrics_path
