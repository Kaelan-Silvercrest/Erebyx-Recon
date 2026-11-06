"""
core/loader.py

Auto-discovery buat semua modul di modules/generic/ dan modules/indonesia/.
Cara kerja: scan tiap .py file di folder modules/**, import, cari class
yang inherit dari OSINTModule, lalu daftarin ke registry.

Kamu TIDAK perlu edit file ini tiap nambah modul baru — cukup taruh file
modul baru di folder yang sesuai, ikutin kontrak di module_base.py, dan
otomatis ke-detect pas CLI dijalankan.
"""

import importlib
import inspect
import pkgutil
from pathlib import Path

from erebyx.core.module_base import OSINTModule

MODULES_ROOT = Path(__file__).parent.parent / "modules"


def discover_modules() -> dict[str, type[OSINTModule]]:
    """
    Scan semua modul di bawah modules/ rekursif, lalu return
    dict {module_name: ModuleClass}.
    """
    registry: dict[str, type[OSINTModule]] = {}

    package_path = [str(MODULES_ROOT)]
    for _, module_name, is_pkg in pkgutil.walk_packages(package_path, prefix="erebyx.modules."):
        if not is_pkg:
            full_module_path = module_name
        else:
            full_module_path = module_name

        try:
            mod = importlib.import_module(full_module_path)
        except ImportError as e:
            # Be tolerant of optional extras or half-broken package files.
            print(f"[loader] Gagal import {full_module_path}: {e}")
            continue

        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                inspect.isclass(obj)
                and issubclass(obj, OSINTModule)
                and obj is not OSINTModule
                and obj.__module__ == full_module_path
            ):
                registry[obj.name] = obj

    return registry


def get_module(name: str) -> type[OSINTModule] | None:
    """Ambil satu class modul berdasarkan nama (dipanggil dari cli.py)."""
    return discover_modules().get(name)
