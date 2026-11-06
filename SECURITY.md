# Security & Bug Reporting Policy / Kebijakan Pelaporan Keamanan & Bug

[🇮🇩 Bahasa Indonesia](#bahasa-indonesia) | [🇬🇧 English](#english)

---

<a id="bahasa-indonesia"></a>

## 🇮🇩 Bahasa Indonesia

Kami sangat menjaga keamanan, stabilitas, dan etika penggunaan **Erebyx**. Harap patuhi aturan pelaporan berikut sebelum membuat laporan di repositori ini:

### 1. Larangan Keras Membuka *Public Issue* untuk Bug Kritis / Celah Keamanan

**DILARANG KERAS** membuka *Issue* publik, *Pull Request* publik, atau diskusi terbuka di GitHub apabila Anda menemukan:
- Celah keamanan (*security vulnerability*) pada kode Erebyx (misalnya bypass proteksi SSRF, *command/path injection*, kebocoran data sensitif, dll.).
- Bug kritis atau fatal yang menyebabkan kerusakan sistem, *crash* parah, atau perilaku jaringan yang melanggar batas pengaman (*guardrails*).

Semua temuan **kritis, fatal, atau terkait keamanan** WAJIB dilaporkan secara **privat** langsung ke email pribadi pengembang:

- **Email Pengembang:** [ronancalloway@gmail.com](mailto:ronancalloway@gmail.com)
- **Subjek Email:** `[EREBYX SECURITY / CRITICAL BUG] Ringkasan Singkat Temuan`

#### Informasi yang Perlu Disertakan dalam Email:
1. Deskripsi rinci mengenai celah keamanan atau bug kritis yang ditemukan.
2. Langkah-langkah reproduksi (*steps to reproduce*) atau *Proof of Concept* (PoC).
3. Versi Erebyx (`erebyx --version`), versi Python, dan sistem operasi yang digunakan.
4. Dampak potensial dan (jika ada) saran perbaikan.

---

### 2. Kapan Diperbolehkan Membuka *Public Issue* di GitHub?

Jika masalah yang Anda temukan **TIDAK bersifat kritis, TIDAK fatal, dan BUKAN celah keamanan**, Anda **diperkenankan dan dipersilakan** membuka *Public Issue* secara langsung di dalam repositori GitHub ini. Contoh yang boleh dilaporkan lewat *Public Issue*:
- Bug ringan pada tampilan output CLI atau terjemahan bahasa (`id` / `en`).
- Kesalahan ketik (*typo*) atau perbaikan dokumentasi (`README.md`, komentar kode).
- Usulan fitur baru (*feature request*) atau penambahan modul OSINT publik yang sah.
- Pertanyaan seputar instalasi (`install.sh`) atau konfigurasi environment.

---

<a id="english"></a>

## 🇬🇧 English

We take the security, stability, and responsible operation of **Erebyx** seriously. Please follow the reporting rules below before submitting any report to this repository:

### 1. Strict Prohibition on Public Issues for Security Vulnerabilities & Critical/Fatal Bugs

You are **STRICTLY PROHIBITED** from opening a public GitHub Issue, public Pull Request, or public discussion if you discover:
- Any security vulnerability in Erebyx (e.g., SSRF guardrail bypass, path/command injection, unintended data exposure, etc.).
- Any critical or fatal bug that causes severe crashes, data corruption, or unintended network behavior outside the tool's safety guardrails.

All **security vulnerabilities, critical bugs, or fatal defects** MUST be reported **privately** via direct email to the developer:

- **Developer Email:** [ronancalloway@gmail.com](mailto:ronancalloway@gmail.com)
- **Suggested Subject Line:** `[EREBYX SECURITY / CRITICAL BUG] Short Summary of Finding`

#### What to Include in Your Private Report:
1. A clear description of the vulnerability or critical/fatal bug.
2. Exact steps to reproduce or a minimal Proof of Concept (PoC).
3. Your Erebyx version (`erebyx --version`), Python version, and operating system.
4. Potential impact and (optionally) suggested remediation.

---

### 2. When Are Public GitHub Issues Allowed?

If the issue you found is **non-critical, non-fatal, and does NOT involve a security vulnerability**, you are **welcome and encouraged** to open a public Issue directly in this repository. Examples of permitted public Issues include:
- Minor CLI formatting glitches or translation (`id` / `en`) fixes.
- Documentation improvements or typos.
- Feature requests or proposals for new legitimate public OSINT modules.
- General installation (`install.sh`) or environment questions.

