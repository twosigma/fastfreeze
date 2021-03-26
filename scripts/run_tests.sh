#!/bin/bash
set -eux

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

echo passphrase > $IMAGE_DIR/encryption_key

docker stop ff || true

sudo bash -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'

# In the following, we don't need cap_sys_ptrace, but it makes Docker
# relax its seccomp filters on kcmp(), which CRIU needs.

# Forget to put cap-add, and get Permission Denied
docker run \
  --rm \
  --user nobody \
  --cap-add=cap_sys_ptrace \
  --name ff \
  --mount type=bind,source=$IMAGE_DIR,target=$IMAGE_DIR \
  --env FF_METRICS_RECORDER=$IMAGE_DIR/show_metrics.sh \
  fastfreeze-test:latest \
  fastfreeze run -v \
    --image-url $IMAGE_DIR/test-image \
    --on-app-ready "touch $IMAGE_DIR/run1.ready" \
    --passphrase-file $IMAGE_DIR/encryption_key -- \
    sleep 30d &

timeout 10 bash -c "while [ ! -e $IMAGE_DIR/run1.ready ]; do sleep 0.1; done"

docker exec --env FF_METRICS_RECORDER=$IMAGE_DIR/show_metrics.sh ff fastfreeze checkpoint -v

wait

docker run \
  --rm \
  --user nobody \
  --cap-add=cap_sys_ptrace \
  --name ff \
  --mount type=bind,source=$IMAGE_DIR,target=$IMAGE_DIR \
  --env FF_METRICS_RECORDER=$IMAGE_DIR/show_metrics.sh \
  fastfreeze-test:latest \
  fastfreeze run -v \
    --image-url $IMAGE_DIR/test-image \
    --on-app-ready "touch $IMAGE_DIR/run2.ready" \
    --passphrase-file $IMAGE_DIR/encryption_key -- \
    sleep 30d &

timeout 10 bash -c "while [ ! -e $IMAGE_DIR/run2.ready ]; do sleep 0.1; done"

docker exec --env FF_METRICS_RECORDER=$IMAGE_DIR/show_metrics.sh ff fastfreeze wait -v

docker exec ff fastfreeze checkpoint

wait
