"""
erebyx/i18n.py

Sistem bahasa (i18n) sederhana untuk output Erebyx.

Urutan prioritas pemilihan bahasa:
    1. Flag CLI  `--lang en|id`
    2. Environment variable `EREBYX_LANG`
    3. File konfigurasi `~/.config/erebyx/config` (ditulis oleh install.sh
       atau `erebyx --set-lang`)
    4. Default: English

Catatan desain: key JSON pada hasil modul SELALU bahasa Inggris (skema stabil
untuk diproses script lain). Yang diterjemahkan adalah teks yang dibaca manusia:
pesan, warning, catatan, deskripsi modul, dan label pada output `pretty`.
"""

import os
from pathlib import Path

SUPPORTED_LANGUAGES = ("en", "id")
DEFAULT_LANGUAGE = "en"


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "erebyx" / "config"


_current_language: str | None = None


def _normalize(lang: str | None) -> str | None:
    if not lang:
        return None
    lang = lang.strip().lower()
    return lang if lang in SUPPORTED_LANGUAGES else None


def load_saved_language() -> str | None:
    path = config_path()
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() == "lang":
                return _normalize(value)
    except OSError:
        return None
    return None


def save_language(lang: str) -> Path:
    normalized = _normalize(lang)
    if normalized is None:
        raise ValueError(f"unsupported language: {lang}")
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"lang={normalized}\n", encoding="utf-8")
    return path


def resolve_language(cli_lang: str | None = None) -> str:
    return (
        _normalize(cli_lang)
        or _normalize(os.environ.get("EREBYX_LANG"))
        or load_saved_language()
        or DEFAULT_LANGUAGE
    )


def set_language(lang: str | None) -> str:
    global _current_language
    _current_language = _normalize(lang) or DEFAULT_LANGUAGE
    return _current_language


def get_language() -> str:
    global _current_language
    if _current_language is None:
        _current_language = resolve_language()
    return _current_language


def t(key: str, **kwargs: object) -> str:
    """Terjemahkan `key` ke bahasa aktif. Fallback: English, lalu key itu sendiri."""
    lang = get_language()
    template = MESSAGES.get(lang, {}).get(key) or MESSAGES["en"].get(key) or key
    try:
        return template.format(**kwargs)
    except (KeyError, IndexError, ValueError):
        return template


def label(key: str) -> str:
    """Label ramah-manusia untuk key data pada output `pretty`."""
    lang = get_language()
    return LABELS.get(lang, {}).get(key) or LABELS["en"].get(key) or key


# --------------------------------------------------------------------------
# Pesan
# --------------------------------------------------------------------------

MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        # CLI
        "cli.description": (
            "Erebyx — deep OSINT & recon for public domains/organizations and "
            "authorized audits (use is bound by LICENSE & DISCLAIMER.md)"
        ),
        "cli.help.module": (
            "Module to run (see --list-modules), or 'all' to run every active "
            "module that matches the target"
        ),
        "cli.help.target": "Target for the selected module (domain, email, or local username)",
        "cli.help.list": "Show all available modules with their descriptions",
        "cli.help.output": "Output format (default: pretty)",
        "cli.help.export": "Save JSON results to the erebyx-output/ folder",
        "cli.help.lang": "Output language for this run only (en / id)",
        "cli.help.set_lang": "Save the default output language permanently (en / id)",
        "cli.no_modules": "No modules registered yet.",
        "cli.module_not_found": "Module '{module}' not found. Run --list-modules to see what is available.",
        "cli.invalid_target": "Target '{target}' is not valid for module '{module}'.",
        "cli.save_failed": "Failed to save results: {error}",
        "cli.saved": "Results saved: {path}",
        "cli.no_matching": "No active module matches target '{target}'.",
        "cli.report_failed": "Failed to save combined report: {error}",
        "cli.report_saved": "Combined report saved: {path}",
        "cli.status_ok": "OK",
        "cli.status_fail": "FAILED",
        "cli.sources": "Sources",
        "cli.time": "Time",
        "cli.error": "Error",
        "cli.cancelled": "Cancelled by user.",
        "cli.lang_saved": "Default language set to '{lang}' (saved in {path}).",
        "cli.lang_save_failed": "Failed to save language setting: {error}",
        "cli.yes": "yes",
        "cli.no": "no",
        "cli.none": "-",
        # Module descriptions
        "module_desc.domain_lookup": "Deep domain recon: RDAP, full DNS, SPF/DMARC/CAA & CT subdomains",
        "module_desc.email_check": "Email validation, role/disposable detection & domain MX/SPF/DMARC audit",
        "module_desc.public_contact_lookup": "Organization role emails, RFC 9116 security.txt & HTTP security headers",
        "module_desc.username_check": "Offline username audit: format, entropy, naming style & impersonation risk",
        "module_desc.domain_id_lookup": "PANDI RDAP lookup, .id zone classification & DNS for .id domains",
        "module_desc.ahu_lookup": "Not available yet: AHU (Kemenkumham) legal entity lookup",
        "module_desc.npwp_oss_lookup": "Not available yet: OSS business lookup (NIB/NPWP)",
        "module_desc.sipp_lookup": "Not available yet: Supreme Court SIPP public case lookup",
        # Common errors
        "err.invalid_domain": "Invalid domain format",
        "err.invalid_email": "Invalid email format",
        "err.invalid_username": "Invalid username format",
        "err.invalid_id_domain": "Target must be a valid .id domain",
        "err.unsafe_host": "Domain cannot be accessed safely: {error}",
        "err.no_ip": "no IP address found",
        "err.private_ip": "private/non-public IP address rejected",
        "err.not_json": "response is not a JSON object",
        "err.not_json_list": "response is not a JSON list",
        "err.not_implemented": "Not implemented yet — see the TODO notes in {file}.",
        # Network / DNS
        "net.timeout": "request timed out",
        "net.connection": "connection failed",
        "dns.nxdomain": "domain does not exist",
        "dns.timeout": "DNS lookup timed out",
        # domain_lookup
        "warn.rdap_unavailable": "RDAP unavailable: {error}",
        "warn.dns": "DNS {rtype}: {error}",
        "warn.ct_unavailable": "Certificate Transparency sources unavailable (crt.sh: {crt}; CertSpotter: {spotter})",
        # public_contact_lookup
        "warn.redirect_offsite": "Redirect to another host not followed: {url} -> {location}",
        "warn.http_status": "HTTP {status} while fetching {url}",
        "warn.truncated": "Content truncated at 512 KB: {url}",
        "warn.fetch_failed": "Failed to fetch {url}: {error}",
        "note.contact": (
            "Only role-based addresses on this domain and RFC 9116 security.txt "
            "metadata are returned; personal addresses are not collected."
        ),
        # email_check
        "email.null_mx": "Domain publishes a null MX and declares it does not accept email.",
        "email.mx_failed": "MX lookup failed: {error}",
        "email.mx_fallback": "No MX record; domain has an A/AAAA fallback.",
        "email.mx_fallback_error": "No MX record; fallback DNS: {error}",
        "email.no_route": "No MX and no A/AAAA fallback found.",
        "email.note": "This check analyzes DNS/domain posture without contacting the mailbox.",
        "spoof.strong": "strong (SPF + enforced DMARC)",
        "spoof.moderate": "moderate (SPF + DMARC monitoring only)",
        "spoof.partial": "partial (SPF or DMARC missing)",
        "spoof.weak": "weak (no SPF/DMARC detected)",
        "spoof.not_applicable": "not applicable (domain does not receive email)",
        # username_check
        "note.username": (
            "Local (offline) check. No platform is contacted and personal "
            "account existence is not enumerated."
        ),
        # domain_id_lookup
        "warn.pandi_rdap": "PANDI RDAP unavailable: {error}",
    },
    "id": {
        # CLI
        "cli.description": (
            "Erebyx — OSINT & recon mendalam untuk domain/organisasi publik dan "
            "audit berizin (penggunaan tunduk pada LICENSE & DISCLAIMER.md)"
        ),
        "cli.help.module": (
            "Modul yang dijalankan (lihat --list-modules), atau 'all' untuk "
            "menjalankan semua modul aktif yang cocok dengan target"
        ),
        "cli.help.target": "Target untuk modul yang dipilih (domain, email, atau username lokal)",
        "cli.help.list": "Tampilkan semua modul yang tersedia beserta deskripsinya",
        "cli.help.output": "Format output (default: pretty)",
        "cli.help.export": "Simpan hasil JSON ke folder erebyx-output/",
        "cli.help.lang": "Bahasa output khusus untuk eksekusi ini (en / id)",
        "cli.help.set_lang": "Simpan bahasa output default secara permanen (en / id)",
        "cli.no_modules": "Belum ada modul yang terdaftar.",
        "cli.module_not_found": "Modul '{module}' tidak ditemukan. Jalankan --list-modules untuk melihat yang tersedia.",
        "cli.invalid_target": "Target '{target}' tidak valid untuk modul '{module}'.",
        "cli.save_failed": "Gagal menyimpan hasil: {error}",
        "cli.saved": "Hasil disimpan: {path}",
        "cli.no_matching": "Tidak ada modul aktif yang cocok untuk target '{target}'.",
        "cli.report_failed": "Gagal menyimpan laporan gabungan: {error}",
        "cli.report_saved": "Laporan gabungan disimpan: {path}",
        "cli.status_ok": "OK",
        "cli.status_fail": "GAGAL",
        "cli.sources": "Sumber",
        "cli.time": "Waktu",
        "cli.error": "Error",
        "cli.cancelled": "Dibatalkan oleh pengguna.",
        "cli.lang_saved": "Bahasa default diatur ke '{lang}' (disimpan di {path}).",
        "cli.lang_save_failed": "Gagal menyimpan pengaturan bahasa: {error}",
        "cli.yes": "ya",
        "cli.no": "tidak",
        "cli.none": "-",
        # Module descriptions
        "module_desc.domain_lookup": "Recon mendalam domain: RDAP, DNS lengkap, SPF/DMARC/CAA & subdomain CT",
        "module_desc.email_check": "Validasi email, deteksi role/disposable & audit MX/SPF/DMARC domain",
        "module_desc.public_contact_lookup": "Email role organisasi, RFC 9116 security.txt & header keamanan HTTP",
        "module_desc.username_check": "Audit lokal username: format, entropi, gaya penamaan & risiko impersonasi",
        "module_desc.domain_id_lookup": "Lookup RDAP PANDI, klasifikasi zona .id & DNS untuk domain .id",
        "module_desc.ahu_lookup": "Belum tersedia: lookup badan hukum AHU Kemenkumham",
        "module_desc.npwp_oss_lookup": "Belum tersedia: lookup badan usaha OSS (NIB/NPWP)",
        "module_desc.sipp_lookup": "Belum tersedia: lookup perkara publik SIPP Mahkamah Agung",
        # Common errors
        "err.invalid_domain": "Format domain tidak valid",
        "err.invalid_email": "Format email tidak valid",
        "err.invalid_username": "Format username tidak valid",
        "err.invalid_id_domain": "Target harus berupa domain .id yang valid",
        "err.unsafe_host": "Domain tidak dapat diakses dengan aman: {error}",
        "err.no_ip": "tidak ada alamat IP",
        "err.private_ip": "alamat IP privat/nonpublik ditolak",
        "err.not_json": "respons bukan objek JSON",
        "err.not_json_list": "respons bukan list JSON",
        "err.not_implemented": "Belum diimplementasi — lihat catatan TODO di {file}.",
        # Network / DNS
        "net.timeout": "waktu permintaan habis (timeout)",
        "net.connection": "koneksi gagal",
        "dns.nxdomain": "domain tidak ditemukan",
        "dns.timeout": "DNS lookup timeout",
        # domain_lookup
        "warn.rdap_unavailable": "RDAP tidak tersedia: {error}",
        "warn.dns": "DNS {rtype}: {error}",
        "warn.ct_unavailable": "Sumber Certificate Transparency tidak tersedia (crt.sh: {crt}; CertSpotter: {spotter})",
        # public_contact_lookup
        "warn.redirect_offsite": "Redirect ke host lain tidak diikuti: {url} -> {location}",
        "warn.http_status": "HTTP {status} saat mengambil {url}",
        "warn.truncated": "Konten dibatasi 512 KB: {url}",
        "warn.fetch_failed": "Gagal mengambil {url}: {error}",
        "note.contact": (
            "Hanya alamat role-based pada domain ini dan metadata RFC 9116 "
            "security.txt yang dikembalikan; alamat personal tidak dikumpulkan."
        ),
        # email_check
        "email.null_mx": "Domain mempublikasikan null MX dan menyatakan tidak menerima email.",
        "email.mx_failed": "MX lookup gagal: {error}",
        "email.mx_fallback": "MX tidak ditemukan; domain memiliki fallback A/AAAA.",
        "email.mx_fallback_error": "MX tidak ada; fallback DNS: {error}",
        "email.no_route": "MX dan fallback A/AAAA tidak ditemukan.",
        "email.note": "Pemeriksaan ini menganalisis DNS/postur domain tanpa menghubungi mailbox.",
        "spoof.strong": "kuat (SPF + DMARC ditegakkan)",
        "spoof.moderate": "sedang (SPF + DMARC hanya monitoring)",
        "spoof.partial": "parsial (SPF atau DMARC tidak ada)",
        "spoof.weak": "lemah (SPF/DMARC tidak terdeteksi)",
        "spoof.not_applicable": "tidak relevan (domain tidak menerima email)",
        # username_check
        "note.username": (
            "Pemeriksaan bersifat lokal (offline). Tidak ada platform yang dihubungi "
            "dan keberadaan akun personal tidak dienumerasi."
        ),
        # domain_id_lookup
        "warn.pandi_rdap": "RDAP PANDI tidak dapat diambil: {error}",
    },
}


# --------------------------------------------------------------------------
# Label untuk output pretty (key data -> teks yang dibaca manusia)
# --------------------------------------------------------------------------

LABELS: dict[str, dict[str, str]] = {
    "en": {
        "rdap": "RDAP",
        "dns_records": "DNS records",
        "email_security": "Email security",
        "subdomains_discovered": "Subdomains discovered",
        "subdomain_count": "Subdomain count",
        "subdomain_source": "Subdomain source",
        "warnings": "Warnings",
        "warning": "Warning",
        "note": "Note",
        "public_role_addresses": "Public role addresses",
        "security_txt": "security.txt",
        "security_txt_present": "security.txt present",
        "http_security_headers": "HTTP security headers",
        "missing_security_headers": "Missing security headers",
        "pages_found": "Pages found",
        "pages_checked": "Pages checked",
        "rdap_pandi": "PANDI RDAP",
        "id_zone": ".id zone",
        "spoofing_protection": "Spoofing protection",
        "dns_status": "DNS Status",
        "reason": "Reason",
        "dns_reason": "Reason",
    },
    "id": {
        "rdap": "RDAP",
        "handle": "Handle",
        "status": "Status",
        "registrar": "Registrar",
        "abuse_contact": "Kontak abuse",
        "dnssec_signed": "DNSSEC aktif",
        "dates": "Tanggal",
        "created": "Dibuat",
        "expires": "Kedaluwarsa",
        "updated": "Diperbarui",
        "created_date": "Tanggal dibuat",
        "expiry_date": "Tanggal kedaluwarsa",
        "updated_date": "Tanggal diperbarui",
        "nameservers": "Nameserver",
        "dns_records": "Record DNS",
        "email_security": "Keamanan email",
        "spf_records": "Record SPF",
        "spf_policy": "Kebijakan SPF",
        "dmarc_records": "Record DMARC",
        "dmarc_policy": "Kebijakan DMARC",
        "has_caa": "Punya CAA",
        "subdomains_discovered": "Subdomain ditemukan",
        "subdomain_count": "Jumlah subdomain",
        "subdomain_source": "Sumber subdomain",
        "warnings": "Peringatan",
        "warning": "Peringatan",
        "note": "Catatan",
        "public_role_addresses": "Alamat role publik",
        "security_txt": "security.txt",
        "security_txt_present": "security.txt tersedia",
        "http_security_headers": "Header keamanan HTTP",
        "missing_security_headers": "Header keamanan yang tidak ada",
        "pages_found": "Halaman ditemukan",
        "pages_checked": "Halaman diperiksa",
        "format_valid": "Format valid",
        "local_part": "Local part",
        "base_mailbox": "Mailbox dasar",
        "plus_tag": "Plus tag",
        "is_role_account": "Akun role",
        "is_disposable_provider": "Provider sekali pakai",
        "domain": "Domain",
        "mx_records": "Record MX",
        "domain_has_mail_route": "Domain bisa menerima email",
        "fallback_address_records": "Record fallback A/AAAA",
        "spoofing_protection": "Proteksi spoofing",
        "dns_status": "DNS Status",
        "reason": "Reason",
        "dns_reason": "Reason",
        "username": "Username",
        "length": "Panjang",
        "allowed_characters": "Karakter diizinkan",
        "ascii_only": "Hanya ASCII",
        "normalized_lowercase": "Normalisasi huruf kecil",
        "naming_style": "Gaya penamaan",
        "shannon_entropy_bits": "Entropi Shannon (bit)",
        "privileged_or_reserved_pattern": "Pola akun istimewa/reserved",
        "character_breakdown": "Rincian karakter",
        "letters": "Huruf",
        "digits": "Angka",
        "separators": "Pemisah",
        "account_search_performed": "Pencarian akun dilakukan",
        "rdap_pandi": "RDAP PANDI",
        "id_zone": "Zona .id",
        "extension": "Ekstensi",
        "category": "Kategori",
        "requirements": "Syarat umum",
    },
}

