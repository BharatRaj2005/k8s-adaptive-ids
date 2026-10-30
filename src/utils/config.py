"""Project configuration loading and path resolution."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "settings.yaml"


@lru_cache(maxsize=4)
def load_config(path: str | None = None) -> dict[str, Any]:
    """Load the YAML config. IDS_CONFIG overrides the default location."""
    cfg_path = Path(path or os.environ.get("IDS_CONFIG", DEFAULT_CONFIG))
    with open(cfg_path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def project_path(rel: str | Path) -> Path:
    p = Path(rel).expanduser()
    return p if p.is_absolute() else PROJECT_ROOT / p


def get_path(key: str, cfg: dict[str, Any] | None = None) -> Path:
    cfg = cfg or load_config()
    return project_path(cfg["paths"][key])


def class_names(cfg: dict[str, Any] | None = None) -> dict[int, str]:
    cfg = cfg or load_config()
    return {int(k): v for k, v in cfg["classes"].items()}
