#!/usr/bin/env bash
set -euo pipefail

PYTHON=${PYTHON:-python3}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$PYTHON" "$SCRIPT_DIR/run_dump.py" "$@"
