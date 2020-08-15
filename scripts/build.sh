#!/bin/bash
set -ex

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$0")")
cd $SCRIPT_DIR/..

docker build -f scripts/Dockerfile.build . -t fastfreeze-build
docker run fastfreeze-build cat /src/fastfreeze/fastfreeze.tar.xz > ./fastfreeze.tar.xz
docker build -f scripts/Dockerfile.test . -t fastfreeze-test
