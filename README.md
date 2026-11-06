# Erebyx

**Bilingual Documentation / Dokumentasi Dwibahasa:**  
[🇮🇩 Bahasa Indonesia](#bahasa-indonesia) | [🇬🇧 English](#english)

---

<a id="bahasa-indonesia"></a>

## 🇮🇩 Bahasa Indonesia

**Erebyx** adalah toolkit CLI modular (dwibahasa: **Bahasa Indonesia** & **English**) untuk *reconnaissance* data publik domain/organisasi, audit postur keamanan DNS/Email/HTTP, serta pemeriksaan lokal atas target yang Anda miliki atau berwenang periksa.

> **PERINGATAN HUKUM WAJIB:** Penggunaan alat ini tunduk sepenuhnya pada ketentuan di dalam [LICENSE](./LICENSE) (GNU GPLv3 + *Mandatory Legal Disclaimer*) dan [DISCLAIMER.md](./DISCLAIMER.md). Gunakan **HANYA** pada sistem/domain yang Anda miliki atau memiliki izin tertulis resmi (*Rules of Engagement*).

### Batas Penggunaan & Pengaman Bawaan

- Gunakan hanya untuk riset keamanan yang sah dan sistem yang Anda miliki atau mendapat izin tertulis untuk diperiksa.
- **Proteksi SSRF:** Modul kontak menolak resolusi IP privat/loopback/internal.
- **Filter Privasi Role-Based:** Modul `public_contact_lookup` hanya menampilkan alamat email *role-based* organisasi (seperti `security@`, `abuse@`, `contact@`, `csirt@`, `dpo@`) serta metadata standar RFC 9116 (`/.well-known/security.txt`); alamat personal individu diabaikan.
- **Tanpa Eksploitasi / Bypass:** Modul email dan domain menganalisis DNS, RDAP, dan log publik *Certificate Transparency* (`crt.sh` dengan *fallback* otomatis ke `CertSpotter`) tanpa mengirim email ke mailbox atau melewati kontrol akses/CAPTCHA.
- Jangan gunakan untuk *stalking*, *doxxing*, spam, pelecehan, atau aktivitas ilegal yang melanggar UU ITE / UU PDP.

### Instalasi

Tidak perlu aktivasi `venv` manual atau mengetik `python3 main.py`. Cukup:

```bash
git clone https://github.com/Kaelan-Silvercrest/Erebyx-Recon.git
cd Erebyx-Recon
./install.sh
```

Saat menjalankan `./install.sh`, installer akan menanyakan bahasa output default yang ingin Anda gunakan (**Bahasa Indonesia** atau **English**) dalam Bahasa Inggris dan menyimpannya ke `~/.config/erebyx/config`. Anda juga bisa memilih langsung tanpa prompt interaktif:

```bash
./install.sh --lang id   # Bahasa Indonesia
./install.sh --lang en   # English
```

Update: `git pull && ./install.sh` · Hapus: `./install.sh --uninstall`

> Jika muncul pesan `~/.local/bin` belum ada di `PATH`, tambahkan `export PATH="$HOME/.local/bin:$PATH"` ke `~/.bashrc` atau `~/.zshrc`.

### Modul yang Tersedia

| Modul | Kategori | Status | Fungsi |
|---|---|---|---|
| `domain_lookup` | `generic` | Aktif | Ringkasan RDAP (termasuk DNSSEC & kontak abuse), record DNS lengkap (`A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CAA`, `CNAME`), analisis `SPF`/`DMARC`, & enumerasi subdomain pasif via Certificate Transparency (`crt.sh` + fallback `CertSpotter`) |
| `email_check` | `generic` | Aktif | Validasi format email, deteksi akun role & *disposable provider*, lookup MX/fallback DNS, serta evaluasi proteksi spoofing (`SPF` & `DMARC`) |
| `public_contact_lookup` | `generic` | Aktif | Mengambil alamat kontak role organisasi, metadata `/.well-known/security.txt` (RFC 9116), dan audit *security headers* HTTP (`HSTS`, `CSP`, `X-Frame-Options`, dll.) |
| `username_check` | `generic` | Aktif | Audit lokal mendalam (entropi Shannon, konvensi penamaan, deteksi pola akun terprivilese/reserved) tanpa koneksi internet |
| `domain_id_lookup` | `indonesia` | Aktif | Lookup RDAP resmi PANDI (`rdap.pandi.id`), klasifikasi zona `.id` (`.co.id`, `.go.id`, `.ac.id`, `.or.id`, dll. beserta syarat legalitasnya), dan record DNS |
| `ahu_lookup` | `indonesia` | Kerangka | Kerangka modul lookup badan hukum AHU Kemenkumham |
| `npwp_oss_lookup` | `indonesia` | Kerangka | Kerangka modul lookup badan usaha OSS (NIB/NPWP) |
| `sipp_lookup` | `indonesia` | Kerangka | Kerangka modul lookup perkara publik SIPP Mahkamah Agung |

### Pemakaian

```bash
erebyx --list-modules                     # daftar modul
erebyx --version

# Mengganti bahasa output (permanen atau per-eksekusi)
erebyx --set-lang id                      # simpan default Bahasa Indonesia
erebyx --set-lang en                      # simpan default English
erebyx -m domain_lookup -t example.com --lang en

# Pemeriksaan per modul
erebyx -m domain_lookup -t example.com
erebyx -m domain_id_lookup -t pandi.id
erebyx -m email_check -t security@example.com -o json
erebyx -m username_check -t sysadmin_prod
erebyx -m public_contact_lookup -t example.com --export

# Semua modul aktif yang cocok dengan target sekaligus
erebyx -m all -t example.com --export
```

`--export` menyimpan hasil JSON ke folder `erebyx-output/` di direktori kerja saat ini (dapat diubah lewat environment variable `EREBYX_OUTPUT_DIR`).

### Pelaporan Bug & Keamanan

Baca kebijakan lengkap di [SECURITY.md](./SECURITY.md):
- **DILARANG KERAS** membuka *Public Issue* di GitHub untuk celah keamanan, bug kritis, atau error fatal. Laporkan secara privat via email ke: **ronancalloway@gmail.com**.
- Untuk bug ringan/non-kritis, saran fitur, atau perbaikan dokumentasi, Anda diperkenankan membuka *Public Issue* di repositori ini.

### Lisensi & Kebijakan Hukum

Dirilis di bawah lisensi **GNU General Public License v3.0 (GPLv3)** dengan klausul wajib penggunaan keamanan siber. Lihat [LICENSE](./LICENSE), [DISCLAIMER.md](./DISCLAIMER.md), dan [SECURITY.md](./SECURITY.md).

---

<a id="english"></a>

## 🇬🇧 English

**Erebyx** is a modular bilingual (**English** & **Bahasa Indonesia**) CLI toolkit for public domain/organization reconnaissance, DNS/Email/HTTP security posture auditing, and local inspection on targets you own or are explicitly authorized to assess.

> **MANDATORY LEGAL NOTICE:** Use of this tool is strictly governed by [LICENSE](./LICENSE) (GNU GPLv3 + *Mandatory Legal Disclaimer*) and [DISCLAIMER.md](./DISCLAIMER.md). Use **ONLY** on systems/domains you own or have explicit written authorization (*Rules of Engagement*) to test.

### Usage Boundaries & Built-in Guardrails

- Use exclusively for legitimate security research and systems you own or have written permission to inspect.
- **SSRF Protection:** The contact lookup module blocks private, loopback, and non-global IP resolutions.
- **Role-Based Privacy Filter:** `public_contact_lookup` only extracts organizational role-based addresses (such as `security@`, `abuse@`, `contact@`, `csirt@`, `dpo@`) and standard RFC 9116 (`/.well-known/security.txt`) metadata; personal individual email addresses are ignored.
- **No Exploitation / No Bypass:** Email and domain modules analyze DNS, RDAP, and public *Certificate Transparency* logs (`crt.sh` with automatic fallback to `CertSpotter`) without probing mailboxes or bypassing authentication/CAPTCHAs.
- Do not use for stalking, doxxing, spam, harassment, or any unlawful activity.

### Installation

No manual `venv` activation or typing `python3 main.py` required. Simply run:

```bash
git clone https://github.com/Kaelan-Silvercrest/Erebyx-Recon.git
cd Erebyx-Recon
./install.sh
```

During `./install.sh`, the installer will prompt you in English to choose your preferred default output language (**Bahasa Indonesia** or **English**) and save it to `~/.config/erebyx/config`. You can also pass it non-interactively:

```bash
./install.sh --lang en   # English
./install.sh --lang id   # Bahasa Indonesia
```

Update: `git pull && ./install.sh` · Uninstall: `./install.sh --uninstall`

> If `~/.local/bin` is not in your `PATH`, add `export PATH="$HOME/.local/bin:$PATH"` to your `~/.bashrc` or `~/.zshrc`.

### Available Modules

| Module | Category | Status | Description |
|---|---|---|---|
| `domain_lookup` | `generic` | Active | RDAP summary (including DNSSEC & abuse contact), full DNS records (`A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CAA`, `CNAME`), `SPF`/`DMARC` analysis, & passive subdomain discovery via Certificate Transparency (`crt.sh` + `CertSpotter` fallback) |
| `email_check` | `generic` | Active | Email syntax validation, role & disposable provider detection, MX/fallback DNS lookup, and spoofing protection evaluation (`SPF` & `DMARC`) |
| `public_contact_lookup` | `generic` | Active | Extracts organizational role contacts, `/.well-known/security.txt` (RFC 9116) metadata, and HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`, etc.) |
| `username_check` | `generic` | Active | Offline username audit (Shannon entropy, naming convention, privileged/reserved handle detection) with zero network traffic |
| `domain_id_lookup` | `indonesia` | Active | Official PANDI RDAP lookup (`rdap.pandi.id`), `.id` zone classification (`.co.id`, `.go.id`, `.ac.id`, `.or.id`, etc. with legal eligibility requirements), and DNS records |
| `ahu_lookup` | `indonesia` | Skeleton | Planned skeleton for Indonesian AHU legal entity lookup |
| `npwp_oss_lookup` | `indonesia` | Skeleton | Planned skeleton for Indonesian OSS business lookup (NIB/NPWP) |
| `sipp_lookup` | `indonesia` | Skeleton | Planned skeleton for Supreme Court SIPP public case lookup |

### Usage

```bash
erebyx --list-modules                     # list available modules
erebyx --version

# Switch output language (permanently or per run)
erebyx --set-lang en                      # save English as default
erebyx --set-lang id                      # save Bahasa Indonesia as default
erebyx -m domain_lookup -t example.com --lang en

# Run individual modules
erebyx -m domain_lookup -t example.com
erebyx -m domain_id_lookup -t pandi.id
erebyx -m email_check -t security@example.com -o json
erebyx -m username_check -t sysadmin_prod
erebyx -m public_contact_lookup -t example.com --export

# Run all matching active modules at once
erebyx -m all -t example.com --export
```

`--export` saves JSON results into `./erebyx-output/` in the current working directory (customizable via the `EREBYX_OUTPUT_DIR` environment variable).

### Development & Testing

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests
```

### Bug & Security Reporting

Please read [SECURITY.md](./SECURITY.md) before reporting any issue:
- **DO NOT** open a public GitHub Issue for security vulnerabilities, critical bugs, or fatal errors. Report them privately via email to: **ronancalloway@gmail.com**.
- For non-critical, minor bugs, feature requests, or documentation improvements, you are welcome to open a public Issue in this repository.

### License & Legal Policy

Licensed under the **GNU General Public License v3.0 (GPLv3)** with mandatory cybersecurity acceptable-use terms. See [LICENSE](./LICENSE), [DISCLAIMER.md](./DISCLAIMER.md), and [SECURITY.md](./SECURITY.md).
