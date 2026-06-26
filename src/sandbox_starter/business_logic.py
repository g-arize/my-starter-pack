"""Business logic for the starter package.

Developers should replace or extend `execute` with their domain-specific code.
Keep environment parsing and command-line orchestration in `runner.py`.
"""

from __future__ import annotations

from sandbox_starter.config import StarterConfig
from sandbox_starter.models import BusinessResult


def execute(config: StarterConfig) -> BusinessResult:
    """Run the business workflow and return a structured result.

    This default implementation normalizes input text and returns simple
    analytics. Replace this function with the real workflow.
    """

    normalized_text = " ".join(config.input_text.split())
    words = normalized_text.split() if normalized_text else []
    unique_words = {word.lower() for word in words}
    total_word_characters = sum(len(word) for word in words)
    average_word_length = (
        round(total_word_characters / len(words), 2) if words else 0.0
    )
    longest_word = max(words, key=len) if words else ""

    return BusinessResult(
        ok=True,
        message="Starter business logic completed.",
        input_text=config.input_text,
        normalized_text=normalized_text,
        word_count=len(words),
        unique_word_count=len(unique_words),
        character_count=len(normalized_text),
        average_word_length=average_word_length,
        longest_word=longest_word,
        metrics_path=str(config.metrics_path),
    )
