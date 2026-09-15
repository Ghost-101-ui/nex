from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Risk(str, Enum):
    SAFE = "safe"
    CONFIRM = "confirm"


class Phase(str, Enum):
    RECON = "recon"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    UTILITY = "utility"


@dataclass(frozen=True)
class Tool:
    name: str
    phase: Phase
    risk: Risk
    executable: str
    required: tuple[str, ...]
    optional: tuple[str, ...] = ()
