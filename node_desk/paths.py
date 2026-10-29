from __future__ import annotations

import os
import sys
from pathlib import Path


def resource_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))


def default_data_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
    return base / "NodeDesk"


def bundled_core() -> Path:
    return resource_root() / "vendor" / "mihomo.exe"
