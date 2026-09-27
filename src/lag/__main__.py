"""Allow running the package as `python -m lag`."""

import sys

from lag.cli import main

if __name__ == "__main__":
    sys.exit(main())
