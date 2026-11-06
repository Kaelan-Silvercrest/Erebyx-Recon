"""Memungkinkan eksekusi via `python -m erebyx`."""

import sys

from erebyx.core.cli import main

if __name__ == "__main__":
    sys.exit(main())

