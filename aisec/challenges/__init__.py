"""Importing this package registers every challenge."""

from . import (  # noqa: F401
    c01_prompt_injection,
    c02_system_prompt_leak,
    c03_indirect_injection,
    c04_rag_poisoning,
    c05_insecure_output,
    c06_excessive_agency,
    c07_unbounded_consumption,
)
from .base import Attempt, Challenge, Field, Result, all_challenges, get, register

__all__ = [
    "Attempt",
    "Challenge",
    "Field",
    "Result",
    "all_challenges",
    "get",
    "register",
]
