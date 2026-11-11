"""pydecomp - values."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class Val:
    """A statically computed value plus the recipe that produced it."""
    value: Any
    recipe: list[str] = field(default_factory=list)
