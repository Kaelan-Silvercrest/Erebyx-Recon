"""
modules/indonesia/domain_id_lookup.py

Modul: Lookup RDAP & DNS khusus domain .id (dikelola PANDI - Pengelola Nama
Domain Internet Indonesia), beserta klasifikasi zona .id dan syarat entitas
pendaftarnya.
"""

import re
from typing import Any

import requests

from erebyx.core.module_base import ModuleResult, OSINTModule
from erebyx.i18n import get_language, t
from erebyx.modules.generic.domain_lookup import (
    _abuse_contact,
    _rdap_dates,
    _registrar_name,
    _short_net_error,
)
from erebyx.utils.dns_lookup import resolve_records
from erebyx.utils.http_client import HttpClient

PANDI_ZONES: dict[str, dict[str, dict[str, str]]] = {
    ".co.id": {
        "id": {
            "kategori": "Badan Usaha / Komersial",
            "syarat_umum": "SIUP/NIB/Akta Notaris/TDP perusahaan yang sah di Indonesia",
        },
        "en": {
            "kategori": "Commercial / Business Entity",
            "syarat_umum": "Valid Indonesian business registration (NIB/SIUP/Notarial Deed)",
        },
    },
    ".go.id": {
        "id": {
            "kategori": "Instansi Pemerintah Republik Indonesia",
            "syarat_umum": "Surat permohonan resmi pejabat instansi & persetujuan Kominfo",
        },
        "en": {
            "kategori": "Indonesian Government Institution",
            "syarat_umum": "Official agency request letter & Ministry of Communication approval",
        },
    },
    ".ac.id": {
        "id": {
            "kategori": "Perguruan Tinggi Indonesia",
            "syarat_umum": "SK pendirian lembaga pendidikan tinggi dari kementerian terkait",
        },
        "en": {
            "kategori": "Indonesian Higher Education Institution",
            "syarat_umum": "Official ministerial decree of higher-education establishment",
        },
    },
    ".sch.id": {
        "id": {
            "kategori": "Sekolah (SD/SMP/SMA/SMK/Sederajat)",
            "syarat_umum": "SK operasional sekolah & surat kepala sekolah",
        },
        "en": {
            "kategori": "School (Primary/Secondary/Vocational)",
            "syarat_umum": "School operational permit & principal authorization letter",
        },
    },
    ".or.id": {
        "id": {
            "kategori": "Organisasi / Yayasan / Perkumpulan",
            "syarat_umum": "Akta notaris atau SK Kemenkumham organisasi/yayasan",
        },
        "en": {
            "kategori": "Organization / Foundation / Association",
            "syarat_umum": "Notarial deed or Ministry of Law (Kemenkumham) decree",
        },
    },
    ".mil.id": {
        "id": {
            "kategori": "Militer Republik Indonesia (TNI)",
            "syarat_umum": "Otorisasi resmi Mabes TNI / Kementerian Pertahanan",
        },
        "en": {
            "kategori": "Indonesian Armed Forces (TNI)",
            "syarat_umum": "Official TNI HQ / Ministry of Defense authorization",
        },
    },
    ".desa.id": {
        "id": {
            "kategori": "Pemerintah Desa",
            "syarat_umum": "Surat resmi Kepala Desa & registrasi lewat Kominfo",
        },
        "en": {
            "kategori": "Village Government",
            "syarat_umum": "Village Head official letter & Kominfo registration",
        },
    },
    ".net.id": {
        "id": {
            "kategori": "Penyedia Jasa Telekomunikasi / ISP",
            "syarat_umum": "Izin penyelenggaraan telekomunikasi / jaringan di Indonesia",
        },
        "en": {
            "kategori": "Telecommunications / ISP Provider",
            "syarat_umum": "Indonesian telecommunications/network operator license",
        },
    },
    ".web.id": {
        "id": {
            "kategori": "Publik / Komunitas / Personal Indonesia",
            "syarat_umum": "Identitas WNI (KTP/Paspor)",
        },
        "en": {
            "kategori": "Public / Community / Personal (Indonesia)",
            "syarat_umum": "Indonesian citizen ID (KTP/Passport)",
        },
    },
    ".my.id": {
        "id": {
            "kategori": "Personal / Blog Indonesia",
            "syarat_umum": "Identitas pendaftar",
        },
        "en": {
            "kategori": "Personal / Blog (Indonesia)",
            "syarat_umum": "Registrant identity document",
        },
    },
    ".biz.id": {
        "id": {
            "kategori": "UMKM / Bisnis Mikro Indonesia",
            "syarat_umum": "Identitas pendaftar / pelaku usaha",
        },
        "en": {
            "kategori": "Micro/Small Business (UMKM)",
            "syarat_umum": "Registrant / business owner identity",
        },
    },
    ".ponpes.id": {
        "id": {
            "kategori": "Pondok Pesantren",
            "syarat_umum": "Surat pimpinan pondok pesantren",
        },
        "en": {
            "kategori": "Islamic Boarding School (Pondok Pesantren)",
            "syarat_umum": "Authorization letter from boarding school leadership",
        },
    },
}


class DomainIdLookupModule(OSINTModule):
    name = "domain_id_lookup"
    description = "Lookup RDAP PANDI, klasifikasi zona .id, dan DNS untuk domain .id"
    category = "indonesia"
    requires_api_key = False
    rate_limit_seconds = 0.4

    def validate_target(self, target: str) -> bool:
        candidate = target.strip().lower()
        if not candidate or len(candidate) > 253 or " " in candidate:
            return False
        pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+id$"
        return bool(re.fullmatch(pattern, candidate))

    def run(self, target: str) -> ModuleResult:
        domain = target.strip().lower()
        if not self.validate_target(domain):
            return self._fail(target, t("err.invalid_id_domain"))

        client = HttpClient(rate_limit_seconds=self.rate_limit_seconds)
        pandi_rdap_url = f"https://rdap.pandi.id/rdap/domain/{domain}"
        warnings: list[str] = []
        rdap_info: dict[str, Any] = {}

        try:
            response = client.get(
                pandi_rdap_url, headers={"Accept": "application/rdap+json"}
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError(t("err.not_json"))
            dates = _rdap_dates(payload.get("events", []))
            secure_dns = payload.get("secureDNS")
            rdap_info = {
                "handle": payload.get("handle"),
                "registrar": _registrar_name(payload.get("entities", [])),
                "abuse_contact": _abuse_contact(payload.get("entities", [])),
                "status": payload.get("status", []),
                "created_date": dates.get("created"),
                "expiry_date": dates.get("expires"),
                "updated_date": dates.get("updated"),
                "dnssec_signed": (
                    secure_dns.get("delegationSigned")
                    if isinstance(secure_dns, dict)
                    else None
                ),
                "nameservers": [
                    item.get("ldhName")
                    for item in payload.get("nameservers", [])
                    if isinstance(item, dict) and item.get("ldhName")
                ],
            }
        except (requests.RequestException, ValueError) as exc:
            warnings.append(t("warn.pandi_rdap", error=_short_net_error(exc)))

        dns_records: dict[str, list[str]] = {}
        for record_type in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
            records, error = resolve_records(domain, record_type)
            dns_records[record_type] = records
            if error:
                warnings.append(t("warn.dns", rtype=record_type, error=error))

        zone_meta = _classify_id_zone(domain)

        return self._success(
            target=domain,
            data={
                "domain": domain,
                "zona_pandi": zone_meta,
                "rdap_pandi": rdap_info,
                "dns_records": dns_records,
                "warnings": warnings,
            },
            source_urls=[pandi_rdap_url],
        )


def _classify_id_zone(domain: str, lang: str | None = None) -> dict[str, str]:
    active_lang = lang or get_language()
    lang_key = "id" if active_lang == "id" else "en"
    for suffix, info_by_lang in PANDI_ZONES.items():
        if domain.endswith(suffix):
            info = info_by_lang[lang_key]
            return {
                "ekstensi": suffix,
                "kategori": info["kategori"],
                "syarat_umum": info["syarat_umum"],
            }
    if lang_key == "id":
        return {
            "ekstensi": ".id (Anything .id / Top-Level)",
            "kategori": "Umum / Organisasi / Personal (.id langsung)",
            "syarat_umum": "Terbuka sesuai ketentuan registrasi PANDI",
        }
    return {
        "ekstensi": ".id (Anything .id / Top-Level)",
        "kategori": "General / Organization / Personal (direct .id)",
        "syarat_umum": "Open registration under PANDI terms",
    }
