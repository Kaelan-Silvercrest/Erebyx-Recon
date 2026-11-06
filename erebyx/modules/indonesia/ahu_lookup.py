"""
modules/indonesia/ahu_lookup.py

Modul: cek status badan hukum (PT, Yayasan, Perkumpulan) lewat sistem
AHU (Administrasi Hukum Umum) Kemenkumham — data publik soal legalitas
suatu badan hukum di Indonesia.

CATATAN PENTING:
- ahu.go.id punya layanan publik "Pencarian Nama Perseroan" yang bisa
  diakses tanpa login untuk cek ketersediaan/status nama PT
- Perlu riset apakah ada endpoint JSON yang dipanggil di balik layar
  (buka Network tab di browser pas search di ahu.go.id, biasanya web
  modern manggil endpoint API internal yang bisa langsung dipanggil
  tanpa perlu parse HTML)

TODO implementasi:
1. Inspeksi network request yang dipanggil halaman pencarian AHU
2. Replikasi request itu (header, payload) di modul ini
3. Parse response jadi struktur data yang konsisten
"""

from erebyx.core.module_base import ModuleResult, OSINTModule
from erebyx.i18n import t


class AhuLookupModule(OSINTModule):
    name = "ahu_lookup"
    description = "Belum tersedia: lookup badan hukum AHU Kemenkumham"
    category = "indonesia"
    requires_api_key = False

    def validate_target(self, target: str) -> bool:
        # Target di sini berupa nama badan hukum, bukan nomor
        candidate = target.strip()
        return len(candidate) >= 3 and "\n" not in candidate and "\r" not in candidate

    def run(self, target: str) -> ModuleResult:
        # TODO: implementasi request ke endpoint AHU

        data = {
            "nama_dicari": target,
            "status": None,          # TODO: "terdaftar" / "tersedia" / dll
            "nomor_sk": None,        # TODO
            "tanggal_sk": None,      # TODO
            "jenis_badan_hukum": None,  # TODO: PT / Yayasan / Perkumpulan
        }

        return self._fail(
            target,
            t("err.not_implemented", file="ahu_lookup.py"),
        )
