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
cat <<- EOF > $IMAGE_DIR/show_metrics.sh
#!/bin/bash
echo -n "Metric: "
echo "\$@" | jq -C .
EOF
chmod +x $IMAGE_DIR/show_metrics.sh

docker stop ff || true

docker run \
  --rm \
  --user nobody \
  --cap-add=cap_sys_ptrace \
  --name ff \
  --mount type=bind,source=$IMAGE_DIR,target=/images \
  --env FF_METRICS_RECORDER=/images/show_metrics.sh \
  fastfreeze-test:latest \
  fastfreeze run -v --image-url file:/images/test-1 -- sleep 30d &
sleep 2 # wait for app started

# Forget to put cap-add, and get Permission Denied

docker exec --env FF_METRICS_RECORDER=/images/show_metrics.sh ff fastfreeze checkpoint -v

wait

docker run \
  --rm \
  --user nobody \
  --cap-add=cap_sys_ptrace \
  --name ff \
  --mount type=bind,source=$IMAGE_DIR,target=/images \
  --env FF_METRICS_RECORDER=/images/show_metrics.sh \
  fastfreeze-test:latest \
  fastfreeze run -v --image-url file:/images/test-1 -- sleep 30d &
sleep 2 # wait for app restore

docker exec ff fastfreeze checkpoint

wait
