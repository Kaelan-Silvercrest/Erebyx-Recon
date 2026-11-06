"""
core/module_base.py

Kontrak dasar yang wajib dipenuhi setiap modul OSINT.
Setiap file modul (di modules/generic/ atau modules/indonesia/) harus
punya satu class yang inherit dari OSINTModule ini.

Kenapa pakai abstract base class:
- Memaksa struktur output yang konsisten antar modul (biar gampang
  digabung/diproses lanjut, misal oleh AI analysis layer nanti)
- Loader (core/loader.py) auto-discover class ini lewat introspection,
  jadi kamu tinggal taruh file baru, tidak perlu daftar manual di tempat lain
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ModuleResult:
    """
    Struktur output standar yang wajib dikembalikan tiap modul.
    Konsisten di semua modul supaya gampang di-serialize (JSON/export)
    dan gampang dibaca ulang oleh layer AI analysis nanti.
    """
    module_name: str
    target: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    source_urls: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module_name,
            "target": self.target,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "source_urls": self.source_urls,
            "timestamp": self.timestamp,
        }


class OSINTModule(ABC):
    """
    Base class abstrak. Semua modul WAJIB inherit dari sini.

    Atribut wajib yang harus di-override di tiap subclass:
        name        : str  -> identifier unik modul (dipakai di CLI --module)
        description : str  -> penjelasan singkat buat --list-modules
        category    : str  -> "generic" atau "indonesia" (atau kategori lain nanti)

    Method wajib:
        run(target) -> ModuleResult
    """

    name: str = "base_module"
    description: str = "Belum ada deskripsi."
    category: str = "uncategorized"

    # TODO: tambahin flag ini per-modul kalau butuh API key / rate limit khusus
    requires_api_key: bool = False
    rate_limit_seconds: float = 1.0

    @abstractmethod
    def run(self, target: str) -> ModuleResult:
        """
        Logika utama modul. WAJIB di-override.

        Args:
            target: input yang mau diperiksa (domain, username, email, NPWP, dst
                    — tergantung jenis modulnya)

        Returns:
            ModuleResult — gunakan helper _success() / _fail() di bawah
            biar formatnya konsisten.
        """
        raise NotImplementedError

    def validate_target(self, target: str) -> bool:
        """
        Opsional di-override tiap modul untuk validasi format input
        sebelum request dikirim (misal cek format NPWP 15 digit,
        format email valid, dst). Default: selalu valid.
        """
        return bool(target and target.strip())

    # ---- helper, tidak perlu diubah di subclass ----

    def _success(self, target: str, data: dict[str, Any],
                 source_urls: list[str] | None = None) -> ModuleResult:
        return ModuleResult(
            module_name=self.name,
            target=target,
            success=True,
            data=data,
            source_urls=source_urls or [],
        )

    def _fail(self, target: str, error: str) -> ModuleResult:
        return ModuleResult(
            module_name=self.name,
            target=target,
            success=False,
            error=error,
        )
