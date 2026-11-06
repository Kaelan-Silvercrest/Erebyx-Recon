"""
modules/indonesia/npwp_oss_lookup.py

Modul: cek data publik badan usaha lewat sistem OSS (Online Single
Submission) milik pemerintah Indonesia — ini data publik yang legal
diakses untuk verifikasi legalitas perusahaan.

CATATAN PENTING sebelum implementasi:
- Cek dulu apakah OSS (oss.go.id) punya endpoint publik resmi atau
  cuma web form biasa (kemungkinan besar perlu scraping form, bukan API
  resmi — cek robots.txt dan ToS mereka dulu)
- NIB (Nomor Induk Berusaha) biasanya yang dipakai buat lookup di OSS,
  bukan NPWP langsung — perlu dicek alur yang benar di web OSS-nya
- Kalau OSS butuh captcha, modul ini perlu strategi tambahan
  (captcha solving di luar scope skeleton ini — bisa jadi scope manual
  verifikasi dulu sebelum full-automated)

TODO implementasi:
1. Riset dulu endpoint/flow yang dipakai oss.go.id buat public lookup
2. Kalau ada API resmi publik, pakai itu (lebih stabil daripada scraping)
3. Kalau cuma web form, pertimbangkan Selenium/Playwright buat handle
   form submission + captcha (kalau ada)
"""

from erebyx.core.module_base import ModuleResult, OSINTModule
from erebyx.i18n import t


class NpwpOssLookupModule(OSINTModule):
    name = "npwp_oss_lookup"
    description = "Belum tersedia: lookup badan usaha OSS (NIB/NPWP)"
    category = "indonesia"
    requires_api_key = False  # TODO: update kalau ternyata butuh registrasi API

    def validate_target(self, target: str) -> bool:
        # NPWP format Indonesia: 15 atau 16 digit (format baru pakai NIK 16 digit)
        digits_only = target.strip().replace(".", "").replace("-", "")
        return digits_only.isdigit() and len(digits_only) in (15, 16)

    def run(self, target: str) -> ModuleResult:
        # TODO: implementasi scraping/API call ke OSS
        # Placeholder struktur data yang diharapkan:

        data = {
            "nib": None,              # TODO
            "nama_perusahaan": None,  # TODO
            "status_npwp": None,      # TODO (aktif/nonaktif)
            "klasifikasi_usaha": None,  # TODO (KBLI)
            "alamat_terdaftar": None,   # TODO
            "tanggal_terbit": None,     # TODO
        }

        return self._fail(
            target,
            t("err.not_implemented", file="npwp_oss_lookup.py"),
        )
