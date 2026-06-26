"""OpenSRE platform runtime services.

This package intentionally shares its name with Python's stdlib ``platform`` module.
Expose the stdlib module's public API here as well so existing ``import platform``
callers continue to behave as expected while project code can import subpackages
such as ``platform.analytics``.
"""

from __future__ import annotations

import importlib.util
import sys
import sysconfig
from pathlib import Path


def _is_frozen() -> bool:
    """Check if running in a PyInstaller frozen build."""
    return getattr(sys, "frozen", False)


_REENTRANCY_GUARD = "_opensre_platform_loading"


def _load_stdlib_platform():
    """Load the stdlib ``platform`` module.

    In frozen PyInstaller builds, the stdlib ``platform`` module is a
    built-in/frozen module not available as a ``.py`` file. Handle both
    frozen and non-frozen environments.
    """
    # In frozen builds, try importing the stdlib platform directly by
    # temporarily removing our package from sys.modules.
    if _is_frozen():
        # Guard against re-entrant calls using a separate key so we
        # don't shadow the real "platform" entry that importlib needs.
        if sys.modules.get(_REENTRANCY_GUARD):
            raise ImportError(
                "Recursive platform load detected — stdlib platform "
                "module is not available in this frozen bundle"
            )

        prev = sys.modules.pop("platform", None)
        sys.modules[_REENTRANCY_GUARD] = True
        try:
            import platform as stdlib_platform

            # If importlib resolved back to our own package (detected
            # by the analytics subpackage attribute), the stdlib
            # module is genuinely missing.
            if hasattr(stdlib_platform, "analytics"):
                raise ImportError("stdlib platform module not available in frozen bundle")
            return stdlib_platform
        finally:
            sys.modules.pop(_REENTRANCY_GUARD, None)
            # Always restore the original state.
            sys.modules.pop("platform", None)
            if prev is not None:
                sys.modules["platform"] = prev

    # Non-frozen: load from stdlib file path
    stdlib_dir = sysconfig.get_path("stdlib")
    if stdlib_dir is not None and (Path(stdlib_dir) / "platform.py").is_file():
        stdlib_path = Path(stdlib_dir) / "platform.py"
        spec = importlib.util.spec_from_file_location("_opensre_stdlib_platform", stdlib_path)
        if spec is not None and spec.loader is not None:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

    raise ImportError(
        "Unable to load stdlib platform module — sysconfig path "
        f"{stdlib_dir!r} does not contain platform.py"
    )


_stdlib_platform = _load_stdlib_platform()

for _name in dir(_stdlib_platform):
    if _name.startswith("__") and _name not in {"__all__", "__version__"}:
        continue
    globals()[_name] = getattr(_stdlib_platform, _name)

__all__ = tuple(name for name in dir(_stdlib_platform) if not name.startswith("_"))
