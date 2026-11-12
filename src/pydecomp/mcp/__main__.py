"""``python -m pydecomp.mcp`` starts the stdio server."""
from __future__ import annotations

import sys

from ..mcp.server import main

if __name__ == "__main__":
    sys.exit(main())
