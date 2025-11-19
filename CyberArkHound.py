"""Legacy single-file script retained for backward compatibility.

Prefer using the modular package entrypoint:

    python -m cyberarkhound.cli --help

This file now proxies arguments to the package CLI.
"""
from cyberarkhound.cli import main as cli_main
import sys

if __name__ == "__main__":  # pragma: no cover
    sys.exit(cli_main())
