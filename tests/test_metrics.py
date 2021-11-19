from common import * # '*' is important, otherwise before_* hooks don't run
import os
import json

# TODO test encryption
# TODO test time userspace and namespace virt
# TODO test pretty much all the CLI options
# Why is criu <defunct>

def test_metrics():
    metrics_cmd = f"{TEST_DIR}/metrics.sh"
    metrics_path = f"{TEST_DIR}/metrics"

    metrics_script = f"""
    #!/bin/bash
    echo $1 >> {metrics_path}
    """

    def before_fn():
        with open(metrics_cmd, 'w') as f:
            f.write(metrics_script)
        os.chmod(metrics_cmd, 0o777)

    ff_env={"FF_METRICS_CMD": metrics_cmd}
    template_test(ff_env=ff_env, before_fn=before_fn)

    with open(metrics_path, 'r') as f:
        metrics = [json.loads(line) for line in f.readlines()]

    eprint("------- Metrics -------", color='1;36')
    for m in metrics:
        eprint(f"   -> {m['action']} <-", color='0;33')
        eprint(m)

    actions = [m['action'] for m in metrics]
    assert actions == [
        # 1) Run from scratch
        'fetch_manifest',
        'run_from_scratch',
        # 2) Checkpoint
        'checkpoint_start',
        'checkpoint',
        'run', # This is the termination of 1) Run from scratch
        # 3) Restore
        'fetch_manifest',
        'restore',
        # 4) Checkpoint
        'checkpoint_start',
        'checkpoint',
        'run', # This is the termination of 3) Restore
    ]
