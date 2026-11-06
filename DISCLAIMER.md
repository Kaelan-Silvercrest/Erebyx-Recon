# Legal Disclaimer, Acceptable Use Policy (AUP) & Rules of Engagement

> **PERINGATAN KERAS / CRITICAL WARNING**
> Alat ini melakukan kueri jaringan aktif dan pasif (DNS, RDAP, Certificate Transparency, dan HTTP/HTTPS inspection). Gunakan **HANYA** pada domain, infrastruktur, atau entitas yang Anda miliki secara sah atau telah memberikan izin tertulis eksplisit (*Authorized Rules of Engagement*).

---

## 1. Tujuan Penggunaan yang Sah (*Authorized Scope*)

Perangkat lunak ini dibuat untuk kalangan profesional keamanan siber (*Blue Team*, *Red Team* berizin, *Bug Bounty Hunter* sesuai ruang lingkup program, dan peneliti tata kelola TI) guna:
- Mengidentifikasi postur keamanan domain dan konfigurasi email (`SPF`, `DMARC`, `MX`, `CAA`, `DNSSEC`).
- Melakukan inventarisasi permukaan serangan eksternal (*External Attack Surface Management* / EASM) melalui log publik *Certificate Transparency* (`crt.sh`).
- Memeriksa ketersediaan jalur pelaporan kerentanan resmi (`/.well-known/security.txt` sesuai RFC 9116) dan kontak peranan organisasi (*role-based organizational contacts*).
- Memvalidasi informasi registrasi domain publik melalui protokol resmi RDAP (termasuk PANDI `.id` dan IANA RDAP).

## 2. Aktivitas yang Dilarang Keras (*Prohibited Conduct*)

Pengguna **DILARANG KERAS** menggunakan alat ini untuk:
1. **Doxxing & Pelanggaran Privasi Individu:** Mengumpulkan, menyimpan, menyebarkan, atau menargetkan data pribadi individu (*Personally Identifiable Information* / PII) tanpa dasar hukum yang sah.
2. **Akses Tanpa Izin (*Unauthorized Access*):** Mencoba mengeksploitasi kerentanan, melakukan *brute-force*, melewati batas autentikasi, atau mengakali mekanisme proteksi (*WAF*, *rate limiter*, *CAPTCHA*).
3. **Gangguan Layanan (*Denial of Service*):** Menghapus batasan laju (*rate limit*) untuk membanjiri server target atau layanan pihak ketiga dengan trafik berlebih.
4. **Pengintaian Ilegal:** Memata-matai, menguntit (*stalking*), memeras, atau melakukan rekayasa sosial (*social engineering* / *phishing*) terhadap individu maupun organisasi tanpa izin kontrak pengujian.

## 3. Kepatuhan Hukum (*Regulatory Compliance*)

Setiap pengguna wajib mematuhi hukum dan perundang-undangan yang berlaku di yurisdiksi tempat pengguna berada maupun tempat target berada:
- **Indonesia:**
  - **UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (UU PDP):** Melarang pengumpulan dan pemrosesan data pribadi secara melawan hukum.
  - **UU No. 11 Tahun 2008 jo. UU No. 19 Tahun 2016 jo. UU No. 1 Tahun 2024 tentang Informasi dan Transaksi Elektronik (UU ITE):** Pasal 30 melarang akses sistem elektronik milik orang lain tanpa hak atau secara melawan hukum.
- **Internasional:**
  - *Computer Fraud and Abuse Act* (CFAA - Amerika Serikat)
  - *Computer Misuse Act 1990* (Inggris Raya)
  - *General Data Protection Regulation* (GDPR - Uni Eropa)

## 4. Batasan Teknis & Pengaman Bawaan (*Built-in Guardrails*)

Untuk mencegah penyalahgunaan di luar kendali, alat ini menerapkan pengaman teknis yang **tidak boleh dinonaktifkan untuk tujuan melanggar hukum**:
- **SSRF & Private Network Protection:** Menolak pemindaian terhadap alamat IP lokal/privat (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local, dll.).
- **Role-Based Contact Filtering:** Hanya mengambil alamat email fungsional organisasi (seperti `security@`, `abuse@`, `contact@`, `support@`) dan membuang alamat email personal dari hasil pencarian kontak halaman web.
- **Rate Limiting & Identitas User-Agent:** Membatasi jeda antar permintaan HTTP dan menyertakan identitas `User-Agent` penelitian yang transparan.

## 5. Pelepasan Tanggung Jawab (*Limitation of Liability*)

PERANGKAT LUNAK INI DISEDIAKAN "SEBAGAIMANA ADANYA" (*AS IS*). PENGEMBANG DAN KONTRIBUTOR TIDAK BERTANGGUNG JAWAB ATAS KERUSAKAN LANGSUNG, TIDAK LANGSUNG, INSIDENTAL, ATAU KONSEKUENSIAL, TERMASUK TUNTUTAN PIDANA MAUPUN PERDATA YANG TIMBUL DARI PENGGUNAAN ATAU PENYALAHGUNAAN ALAT INI. DENGAN MENJALANKAN PERANGKAT LUNAK INI, ANDA MENYATAKAN MEMILIKI OTORISASI HUKUM PENUH ATAS TARGET YANG DIPERIKSA.

