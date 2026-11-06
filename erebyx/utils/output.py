"""Helper untuk menyimpan hasil modul sebagai JSON.

Lokasi default: folder `erebyx-output/` di direktori kerja saat ini.
Bisa diganti lewat environment variable `EREBYX_OUTPUT_DIR`.
(Paket terinstal di site-packages, jadi hasil tidak boleh ditulis ke
folder paket itu sendiri.)
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_DIR = Path(os.environ.get("EREBYX_OUTPUT_DIR") or Path.cwd() / "erebyx-output")


def save_json(result_dict: dict, target: str, module_name: str) -> Path:
    """
    Simpan hasil modul ke output dengan nama file yang aman.
    """
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    safe_module = re.sub(r"[^A-Za-z0-9_-]", "_", module_name)[:64] or "module"
    safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:80].strip("._-")
    safe_target = safe_target or "target"
    filename = f"{safe_module}_{safe_target}_{timestamp}.json"
    filepath = OUTPUT_DIR / filename

    filepath.write_text(
        json.dumps(result_dict, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return filepath


def save_combined_report(results: list[dict], label: str = "report") -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    safe_label = re.sub(r"[^A-Za-z0-9_-]", "_", label)[:64] or "report"
    filepath = OUTPUT_DIR / f"{safe_label}_{timestamp}.json"
    filepath.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return filepath
