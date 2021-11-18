#!/bin/bash
set -ex

# Note: You may use --debug for building images faster when running tests

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$0")")
cd "$SCRIPT_DIR"/..

# Fetch dependencies sources if needed
[ -e deps/criu/Makefile ] || (git submodule sync && git submodule update --init)

BUILD_ENV=()
CARGO_OPTS=()
if [ "$1" == '--debug' ]; then
    BUILD_ENV=("--build-arg" "BUILD=debug")
    CARGO_OPTS=("--build-arg" "CARGO_OPTS=")
fi

docker build -f scripts/Dockerfile.build . -t fastfreeze-build "${BUILD_ENV[@]}" "${CARGO_OPTS[@]}"
docker run fastfreeze-build cat /src/fastfreeze/fastfreeze.tar.xz > ./fastfreeze.tar.xz
docker build -f scripts/Dockerfile.test . -t fastfreeze-test "${BUILD_ENV[@]}"
docker build -f scripts/Dockerfile.test.ff_installed . -t fastfreeze-test-ff-installed
