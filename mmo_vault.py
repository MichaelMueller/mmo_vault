#!/usr/bin/env python3
"""Entry point of the server variant.

Deliberately nothing but a starter. This file sits next to the package
directory of the same name; Python resolves `import mmo_vault` to the package,
while this script runs as __main__. Keeping it empty avoids any doubt about
which of the two is meant.

    python mmo_vault.py setup
    python mmo_vault.py start
    python mmo_vault.py enroll <user>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mmo_vault.server.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
