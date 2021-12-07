from common import * # '*' is important, otherwise before_* hooks don't run
import os
import re

NANOS_IN_SEC = 1_000_000_000

def parse_time_output(stdout):
    #return {"dlsym": 0, "regular": 0}
    results = {}
    for line in stdout.decode().splitlines():
        m = re.search("lookup=(.*) tv_sec=(.*) tv_nsec=(.*)", line)
        assert m != None, f"Failed to parse {line}"
        lookup, tv_sec, tv_nsec = m.groups()
        results[lookup] = float(tv_sec) + float(tv_nsec)/NANOS_IN_SEC
    return results

def template_test_time(env={}, deny={}, using="time_namespace"):
    env['RESUME_PATH'] = f"{TEST_DIR}/resume"

    ff_docker_args = flatten([["--env", f"{k}={v}"] for (k,v) in env.items()])

    # 1) run from scratch
    eprint("------- Run from scratch -------", color='1;36')
    respawn_docker_container(deny=deny)

    ff_run_proc = spawn_docker_exec([
        "unshare", "-Ur",
        "fastfreeze", "run",
        "--image-url", f"{TEST_DIR}/test-image",
        "--on-app-ready", f"touch {TEST_DIR}/run1.ready",
        *FF_ARGS_EXTRA,
        "--",
        "test_apps/bin/time"
    ], docker_args=ff_docker_args, stdout=subprocess.PIPE)

    def check_app_ready():
        check_returncode(ff_run_proc)
        return os.path.isfile(f"{TEST_DIR}/run1.ready")
    wait(check_app_ready)

    # 2) checkpoint
    eprint("------- Checkpoint -------", color='1;36')
    docker_exec(["fastfreeze", "checkpoint", *FF_ARGS_EXTRA])

    stdout, _ = ff_run_proc.communicate()
    times1 = parse_time_output(stdout)
    eprint(f"Before restore: {times1}", color='1;35')

    # userspace virt sets the clock to 0 on start.
    if using == "userspace_virt":
        assert times1['dlsym'] < 10
        assert times1['regular'] < 10

    RESTORE_TIME_OFFSET_SECS = 1000

    # We restore with a time offset created in a time namespace
    # 3) restore
    eprint("------- Restore -------", color='1;36')
    respawn_docker_container(deny=deny)
    ff_run_proc = spawn_docker_exec([
        "test_apps/bin/time_namespace", str(RESTORE_TIME_OFFSET_SECS),
        "fastfreeze", "run",
        "--image-url", f"{TEST_DIR}/test-image",
        "--on-app-ready", f"touch {TEST_DIR}/run2.ready",
        *FF_ARGS_EXTRA,
    ], docker_args=ff_docker_args, stdout=subprocess.PIPE)

    subprocess_run(["touch", f"{TEST_DIR}/resume"])

    # here we wait+check_returncode because we expect the restore
    # command to exit with status=0.
    ff_run_proc.wait()
    check_returncode(ff_run_proc)

    stdout, _ = ff_run_proc.communicate()
    times2 = parse_time_output(stdout)
    eprint(f"After restore: {times2}", color='1;35')

    for t in ['regular', 'dlsym']:
        assert times2[t] - times1[t] < RESTORE_TIME_OFFSET_SECS
        assert times2[t] - times1[t] < RESTORE_TIME_OFFSET_SECS


def test_time_virt_with_time_namespaces():
    template_test_time(using="time_namespace")

def test_time_virt_userspace():
    template_test_time(env={"FF_APP_VIRT_TIME_IN_USERSPACE":"1"},
                       using="userspace_virt")
