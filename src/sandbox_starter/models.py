"""Shared data models for the starter package."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class BusinessResult:
    """Structured result returned by business logic."""

    ok: bool
    message: str
    input_text: str
    normalized_text: str
    word_count: int
    unique_word_count: int
    character_count: int
    average_word_length: float
    longest_word: str
    metrics_path: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""

        return asdict(self)
