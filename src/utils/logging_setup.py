"""Shared logging configuration: stderr plus a rotating file in logs/."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from src.utils.config import PROJECT_ROOT

_CONFIGURED = False


def get_logger(name: str) -> logging.Logger:
    global _CONFIGURED
    if not _CONFIGURED:
        log_dir = PROJECT_ROOT / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        root = logging.getLogger("ids")
        root.setLevel(logging.INFO)
        file_handler = RotatingFileHandler(log_dir / "ids.log", maxBytes=5_000_000, backupCount=3)
        file_handler.setFormatter(fmt)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(fmt)
        root.addHandler(file_handler)
        root.addHandler(stream_handler)
        _CONFIGURED = True
    return logging.getLogger(f"ids.{name}")
