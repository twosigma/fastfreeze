#!/bin/bash
set -ex

# Before running this, run ./build.sh
# TODO We need a bit more tests. Perhaps using something like Python would make
# sense for this.

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$0")")
cd $SCRIPT_DIR/..

IMAGE_DIR=/tmp/ff-test-images
sudo rm -rf $IMAGE_DIR
mkdir -p $IMAGE_DIR
chmod 1777 $IMAGE_DIR # /tmp like permissions

docker stop ff || true

docker run \
  --rm \
  --user nobody \
  --cap-add=cap_sys_ptrace \
  --name ff \
  --mount type=bind,source=$IMAGE_DIR,target=/images \
  fastfreeze-test:latest \
  fastfreeze run --image-url file:/images/test-1 sleep 30d &
sleep 2 # wait for app started

# Forget to put cap-add, and get Permission Denied

docker exec ff fastfreeze checkpoint

wait

docker run \
  --rm \
  --user nobody \
  --cap-add=cap_sys_ptrace \
  --name ff \
  --mount type=bind,source=$IMAGE_DIR,target=/images \
  fastfreeze-test:latest \
  fastfreeze run --image-url file:/images/test-1 sleep 30d &
sleep 2 # wait for app started

docker exec ff fastfreeze checkpoint

wait
