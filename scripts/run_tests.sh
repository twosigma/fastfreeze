#!/bin/bash
set -eu

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$0")")
cd "$SCRIPT_DIR"/..

# install pytest if needed
python -c 'import pytest' &> /dev/null || pip3 install pytest

# build docker images if needed
docker inspect fastfreeze-test-ff-installed &> /dev/null || scripts/build.sh

cd tests
exec python3 -c '
import sys
from pytest import console_main
sys.exit(console_main())
' \
--tb=short "$@"
