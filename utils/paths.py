"""
Single place to ask: “Where do I keep Guardian’s per-user data?”
Windows → %APPDATA%\Guardian
Linux/macOS → ~/.guardian
"""
from __future__ import annotations
import os, sys, json, pathlib as _pl


def get_app_data_dir() -> str:
    if sys.platform == "win32":
        root = _pl.Path(os.environ["APPDATA"]) / "Guardian"
    else:
        root = _pl.Path.home() / ".guardian"
    root.mkdir(parents=True, exist_ok=True)

    # Ensure the two JSON files exist (empty dicts)
    for name in ("wazuh_config.json", "shuffle_config.json"):
        p = root / name
        if not p.exists():
            p.write_text("{}", encoding="utf-8")

    return str(root)
