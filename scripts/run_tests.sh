#!/bin/bash
set -eu

# Before running this, run:
# ./build.sh
# pip3 install pytest

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$0")")
cd "$SCRIPT_DIR"/../tests

exec python3 -c '
import sys
from pytest import console_main
sys.exit(console_main())
' \
--tb=short "$@"
