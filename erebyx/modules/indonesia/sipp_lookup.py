"""
modules/indonesia/sipp_lookup.py

Modul: cek data publik perkara pengadilan lewat SIPP (Sistem Informasi
Penelusuran Perkara) yang dikelola Mahkamah Agung — data perkara perdata/
pidana yang berstatus publik (bukan yang dikecualikan/ditutup).

CATATAN PENTING:
- Tiap pengadilan (PN/PA/PT) punya subdomain SIPP sendiri-sendiri,
  TIDAK ada satu endpoint terpusat — perlu strategi untuk cover banyak
  pengadilan (atau mulai dari beberapa pengadilan besar dulu, misal
  PN Jakarta Pusat, PN Surabaya, dst)
- Data yang sensitif (misal perkara anak, kesusilaan) sering dikecualikan
  dari publikasi — modul ini HARUS menghormati itu, jangan coba bypass
  pengecualian yang memang sengaja ditutup

TODO implementasi:
1. Bikin daftar subdomain SIPP per pengadilan yang mau di-cover
   (data/pengadilan_list.json — bikin file terpisah, jangan hardcode
   di sini biar gampang di-maintain)
2. Riset format URL pencarian perkara di SIPP (biasanya ada halaman
   search by nama pihak)
3. Parse hasil, dengan filter ketat: SKIP kategori perkara yang memang
   dikecualikan dari publikasi (anak, kesusilaan, dll)
"""

from erebyx.core.module_base import ModuleResult, OSINTModule
from erebyx.i18n import t

# TODO: pindahin ke data/pengadilan_list.json kalau daftarnya udah mulai
# panjang, biar tidak perlu edit kode tiap nambah pengadilan baru
EXCLUDED_CATEGORIES = [
    # TODO: lengkapi kategori perkara yang WAJIB di-skip dari hasil
    # karena memang dikecualikan dari publikasi (hormati privasi/hukum)
    "anak",
    "kesusilaan",
]


class SippLookupModule(OSINTModule):
    name = "sipp_lookup"
    description = "Belum tersedia: lookup perkara publik SIPP Mahkamah Agung"
    category = "indonesia"
    requires_api_key = False

    def validate_target(self, target: str) -> bool:
        # Target berupa nama pihak yang dicari
        candidate = target.strip()
        return len(candidate) >= 3 and "\n" not in candidate and "\r" not in candidate

    def run(self, target: str) -> ModuleResult:
        # TODO: implementasi loop ke daftar pengadilan, search nama pihak,
        # filter hasil yang masuk EXCLUDED_CATEGORIES

        data = {
            "nama_dicari": target,
            "perkara_ditemukan": [],  # TODO: list of dict per perkara
            "pengadilan_dicek": [],   # TODO: daftar pengadilan yang di-query
            "catatan": "Perkara dengan kategori dikecualikan "
                       "(anak/kesusilaan) otomatis di-skip dari hasil.",
        }

        return self._fail(
            target,
            t("err.not_implemented", file="sipp_lookup.py"),
        )
