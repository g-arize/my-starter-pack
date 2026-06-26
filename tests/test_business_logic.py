from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

from sandbox_starter.business_logic import execute
from sandbox_starter.config import StarterConfig
from sandbox_starter.metrics import write_load_metrics_from_env, write_metrics
from sandbox_starter.runner import write_output


class BusinessLogicTest(unittest.TestCase):
    def test_execute_normalizes_text_and_counts_words(self) -> None:
        result = execute(
            StarterConfig(input_text="  hello   from    sandbox starter  ")
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.normalized_text, "hello from sandbox starter")
        self.assertEqual(result.word_count, 4)
        self.assertEqual(result.unique_word_count, 4)
        self.assertEqual(result.character_count, 26)
        self.assertEqual(result.average_word_length, 5.75)
        self.assertEqual(result.longest_word, "sandbox")

    def test_write_output_creates_json_file(self) -> None:
        result = execute(StarterConfig(input_text="hello"))

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "nested" / "result.json"
            write_output(
                result,
                StarterConfig(input_text="hello", output_path=output_path),
            )

            self.assertTrue(output_path.exists())
            self.assertIn('"normalized_text": "hello"', output_path.read_text())

    def test_write_metrics_creates_agent_accessible_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_path = Path(tmpdir) / "starter-metrics.md"
            config = StarterConfig(
                input_text="hello metrics",
                metrics_path=metrics_path,
            )
            result = execute(config)

            write_metrics(config, result)

            metrics = metrics_path.read_text(encoding="utf-8")
            self.assertIn("# Starter Package Metrics", metrics)
            self.assertIn("## Business Analytics", metrics)
            self.assertIn("- Word count: `2`", metrics)
            self.assertIn("Environment variables: intentionally not read", metrics)

    def test_package_import_writes_load_metrics_when_path_is_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_path = Path(tmpdir) / "starter-load-metrics.md"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(Path.cwd() / "src")
            env["STARTER_LOAD_METRICS_PATH"] = str(metrics_path)

            subprocess.run(
                [sys.executable, "-c", "import sandbox_starter"],
                check=True,
                env=env,
            )

            metrics = metrics_path.read_text(encoding="utf-8")
            self.assertIn("# Starter Package Load Metrics", metrics)
            self.assertIn("- Package import: `ok`", metrics)
            self.assertIn("Environment variables: intentionally not read", metrics)

    def test_install_trigger_uses_same_load_metrics_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_path = Path(tmpdir) / "install-load-metrics.md"
            old_path = os.environ.get("STARTER_LOAD_METRICS_PATH")
            os.environ["STARTER_LOAD_METRICS_PATH"] = str(metrics_path)
            try:
                write_load_metrics_from_env(
                    trigger="uv pip install -e .",
                    health_label="Editable package install",
                )
            finally:
                if old_path is None:
                    os.environ.pop("STARTER_LOAD_METRICS_PATH", None)
                else:
                    os.environ["STARTER_LOAD_METRICS_PATH"] = old_path

            metrics = metrics_path.read_text(encoding="utf-8")
            self.assertIn("# Starter Package Load Metrics", metrics)
            self.assertIn("uv pip install -e .", metrics)
            self.assertIn("- Editable package install: `ok`", metrics)


if __name__ == "__main__":
    unittest.main()
