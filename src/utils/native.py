"""Native runtime libraries that may be missing on the host.

The LightGBM wheel links against the system OpenMP runtime (libgomp.so.1). When
the libgomp1 package is not installed system-wide, setup.sh extracts the Ubuntu
.deb into vendor/libgomp1 (no root needed). Loading that copy with RTLD_GLOBAL
before importing lightgbm lets the dynamic linker satisfy the dependency by SONAME.
"""
from __future__ import annotations

import ctypes

from src.utils.config import PROJECT_ROOT

_libgomp_source: str | None = None


def ensure_libgomp() -> str | None:
    """Make libgomp.so.1 loadable. Returns 'system', a vendored path, or None."""
    global _libgomp_source
    if _libgomp_source:
        return _libgomp_source
    try:
        ctypes.CDLL("libgomp.so.1")
        _libgomp_source = "system"
        return _libgomp_source
    except OSError:
        pass
    for candidate in sorted((PROJECT_ROOT / "vendor" / "libgomp1").glob("usr/lib/*/libgomp.so.1")):
        ctypes.CDLL(str(candidate), mode=ctypes.RTLD_GLOBAL)
        _libgomp_source = str(candidate)
        return _libgomp_source
    return None


def import_lightgbm():
    """Import lightgbm after making sure its OpenMP dependency can be resolved."""
    ensure_libgomp()
    import lightgbm

    return lightgbm
