from common import *
import pytest


FF_EXTRA_ARGS=["-vvv"]

def template_test(docker_args, docker_image, **kwargs):
    # 1) run from scratch
    eprint("------- Run from scratch -------", color='1;36')
    respawn_docker_container(docker_args, docker_image)
    # It's better to exec the application to be checkpointed: otherwise, if we
    # run the docker init process with the application to be checkpointed, once
    # checkpointed, it will die and terminate the container, leading to the
    # death of the checkpointing command. We would detect an error of the
    # checkpointing command.
    ff_run_proc = spawn_docker_exec([
        "fastfreeze", "run",
        "--image-url", f"{TMP_DIR}/test-image",
        "--on-app-ready", f"touch {TMP_DIR}/run1.ready",
        *FF_EXTRA_ARGS,
        "--",
        "sleep", "30d"
    ], **kwargs)

    def check_app_ready():
        check_returncode(ff_run_proc)
        return os.path.isfile(f"{TMP_DIR}/run1.ready")
    wait(check_app_ready, timeout=10)

    # 2) checkpoint
    eprint("------- Checkpoint -------", color='1;36')
    docker_exec(["fastfreeze", "checkpoint", *FF_EXTRA_ARGS], **kwargs)

    ff_run_proc.wait()
    # The fastfreeze command should return with an error 
    assert ff_run_proc.returncode == 137

    # 3) restore
    eprint("------- Restore -------", color='1;36')
    respawn_docker_container(docker_args, docker_image)
    ff_run_proc = spawn_docker_exec([
        "fastfreeze", "run",
        "--image-url", f"{TMP_DIR}/test-image",
        "--on-app-ready", f"touch {TMP_DIR}/run2.ready",
        *FF_EXTRA_ARGS,
        # omitting the app cmd line to force restore mode
    ], **kwargs)

    def check_app_ready():
        check_returncode(ff_run_proc)
        return os.path.isfile(f"{TMP_DIR}/run2.ready")
    wait(check_app_ready, timeout=10)

    # 4) checkpoint
    eprint("------- Checkpoint after restore -------", color='1;36')
    docker_exec(["fastfreeze", "checkpoint", *FF_EXTRA_ARGS], **kwargs)


def test_no_privileges():
    cleanup_image_dir()
    set_pid_max(10000) # speeds up test
    set_yama_ptrace_scope(0)

    # We don't need CAP_SYS_PTRACE, but it makes Docker relax its seccomp
    # filters on kcmp(), which CRIU needs.
    docker_args = ["--cap-add=cap_sys_ptrace"]
    docker_image = "fastfreeze-test-ff-installed"

    template_test(docker_args, docker_image)

def test_no_privileges_install_error():
    cleanup_image_dir()
    set_yama_ptrace_scope(0)

    docker_args = ["--cap-add=cap_sys_ptrace"]
    docker_image = "fastfreeze-test"
    with pytest.raises(subprocess.CalledProcessError) as e:
        template_test(docker_args, docker_image, stderr=subprocess.PIPE)
    assert "Use `fastfreeze install`" in e.value.stderr


def test_with_namespaces():
    cleanup_image_dir()
    set_yama_ptrace_scope(1)

    docker_args = ["--security-opt", "seccomp=unconfined"]
    docker_image = "fastfreeze-test"
    template_test(docker_args, docker_image)
