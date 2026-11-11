"""Wheel build hook: puts libfasten_core in the wheel when FASTEN_WHEEL_LIB is set.

FASTEN_WHEEL_LIB is the built library, FASTEN_WHEEL_PLAT the platform tag
(for example linux_x86_64 or macosx_11_0_arm64). Without them the wheel is
pure Python and fasten/core_ffi.py finds the library at run time.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        lib = os.environ.get("FASTEN_WHEEL_LIB")
        if self.target_name != "wheel" or version == "editable" or not lib:
            return
        plat = os.environ.get("FASTEN_WHEEL_PLAT")
        if not plat:
            raise ValueError("FASTEN_WHEEL_LIB is set but FASTEN_WHEEL_PLAT is not")
        path = Path(lib)
        if not path.is_file():
            raise FileNotFoundError(f"FASTEN_WHEEL_LIB: {path} not found")
        # ctypes loads the library, so one wheel per platform covers every
        # Python 3 version.
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{plat}"
        build_data["force_include"][str(path)] = f"fasten/{path.name}"
