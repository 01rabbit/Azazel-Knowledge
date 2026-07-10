"""Makes `azazel_grimoire` importable from a src-layout checkout without an
editable install: tests run against the working tree via `sys.path`,
not a pip-installed copy.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
