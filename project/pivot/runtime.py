"""Shared runtime holder for the project's optional operator-established pivot."""
from __future__ import annotations

from config import Config
from pivot.pivot_engine import PivotEngine

_pivot_engine: PivotEngine | None = None


def init_pivot_engine() -> PivotEngine:
    global _pivot_engine
    _pivot_engine = PivotEngine(kali_ip=Config.KALI_IP)
    return _pivot_engine


def get_pivot_engine() -> PivotEngine:
    global _pivot_engine
    if _pivot_engine is None:
        _pivot_engine = init_pivot_engine()
    return _pivot_engine
