#!/usr/bin/env python3
"""
main.py

Shim untuk development langsung dari source tree tanpa instalasi:

    python main.py --list-modules

Untuk pemakaian normal, instal Erebyx (lihat README) lalu cukup jalankan:

    erebyx --list-modules
    erebyx -m domain_lookup -t example.com
"""

import sys

from erebyx.core.cli import main

if __name__ == "__main__":
    sys.exit(main())
