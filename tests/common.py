from docker import *
import pytest
import os

FF_ARGS_EXTRA=["-vv"]

@pytest.fixture(scope="session", autouse=True)
def before_all_tests():
    set_pid_max(10000) # Should speed up tests
    register_app_armor_profiles()

@pytest.fixture(autouse=True)
def before_each_test():
    cleanup_test_dir()
    set_yama_ptrace_scope(1)

def template_test(docker_args=[], docker_image="fastfreeze-test",
                  deny={}, ff_env={}, ff_args=[], before_fn=None,
                  fails_with=None, **kwargs):
    if fails_with:
        with pytest.raises(subprocess.CalledProcessError) as e:
            template_test(docker_args, docker_image, deny, ff_env, ff_args,
                          before_fn, stderr=subprocess.PIPE, **kwargs)
        assert fails_with in e.value.stderr
        return

    if before_fn:
        before_fn()

    ff_docker_args = flatten([["--env", f"{k}={v}"] for (k,v) in ff_env.items()])

    # 1) run from scratch
    eprint("------- Run from scratch -------", color='1;36')
    respawn_docker_container(docker_args, docker_image, deny)
    # It's better to exec the application to be checkpointed: otherwise, if we
    # run the docker init process with the application to be checkpointed, once
    # checkpointed, it will die and terminate the container, leading to the
    # death of the checkpointing command. We would detect an error of the
    # checkpointing command.
    ff_run_proc = spawn_docker_exec([
        "fastfreeze", "run",
        "--image-url", f"{TEST_DIR}/test-image",
        "--on-app-ready", f"touch {TEST_DIR}/run1.ready",
        *ff_args, *FF_ARGS_EXTRA,
        "--",
        "sleep", "30d"
    ], docker_args=ff_docker_args, **kwargs)

    def check_app_ready():
        check_returncode(ff_run_proc)
        return os.path.isfile(f"{TEST_DIR}/run1.ready")
    wait(check_app_ready)

    # 2) checkpoint
    eprint("------- Checkpoint -------", color='1;36')
    docker_exec(["fastfreeze", "checkpoint", *ff_args, *FF_ARGS_EXTRA],
        docker_args=ff_docker_args, **kwargs)

    if os.path.isfile(f"{TEST_DIR}/run2.ready"):
        raise RuntimeError("XXX")

    ff_run_proc.wait()
    # The fastfreeze command should return with an error
    assert ff_run_proc.returncode == 137

    # 3) restore
    eprint("------- Restore -------", color='1;36')
    respawn_docker_container(docker_args, docker_image, deny)
    ff_run_proc = spawn_docker_exec([
        "fastfreeze", "run",
        "--image-url", f"{TEST_DIR}/test-image",
        "--on-app-ready", f"touch {TEST_DIR}/run2.ready",
        *ff_args, *FF_ARGS_EXTRA,
        # omitting the app cmd line to force restore mode
    ], docker_args=ff_docker_args, **kwargs)

    def check_app_ready():
        check_returncode(ff_run_proc)
        return os.path.isfile(f"{TEST_DIR}/run2.ready")
    wait(check_app_ready)

    # 4) checkpoint
    eprint("------- Checkpoint after restore -------", color='1;36')
    docker_exec(["fastfreeze", "checkpoint", *ff_args, *FF_ARGS_EXTRA],
        docker_args=ff_docker_args, **kwargs)

    # Note: notice that there's no finally block to kill the container
    # when things go sideways. This is on purpose so that we can go inspect
    # the container via `docker exec -it ff bash`
