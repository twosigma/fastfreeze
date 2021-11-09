from docker import *
import pytest
import json
import re

# TODO rename FF_METRICS_RECORDER to FF_METRICS_CMD
# TODO test metrics
# TODO test encryption
# TODO test pretty much all the CLI options

FF_EXTRA_ARGS=["-vv"]

def template_test(docker_args=[], docker_image="fastfreeze-test", deny={}, **kwargs):
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
        *FF_EXTRA_ARGS,
        "--",
        "sleep", "30d"
    ], **kwargs)

    def check_app_ready():
        check_returncode(ff_run_proc)
        return os.path.isfile(f"{TEST_DIR}/run1.ready")
    wait(check_app_ready)

    # 2) checkpoint
    eprint("------- Checkpoint -------", color='1;36')
    docker_exec(["fastfreeze", "checkpoint", *FF_EXTRA_ARGS], **kwargs)

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
        *FF_EXTRA_ARGS,
        # omitting the app cmd line to force restore mode
    ], **kwargs)

    def check_app_ready():
        check_returncode(ff_run_proc)
        return os.path.isfile(f"{TEST_DIR}/run2.ready")
    wait(check_app_ready)

    # 4) checkpoint
    eprint("------- Checkpoint after restore -------", color='1;36')
    docker_exec(["fastfreeze", "checkpoint", *FF_EXTRA_ARGS], **kwargs)


####################################


def test_no_privileges():
    # ptrace scope needs to be relaxed when we can't use user namespaces
    set_yama_ptrace_scope(0)
    deny={"user_namespace":"deny"}
    template_test(docker_image="fastfreeze-test-ff-installed", deny=deny)

def test_all_privs_on_ff_installed():
    template_test(docker_image="fastfreeze-test-ff-installed")

def test_no_ptrace():
    deny={"ptrace":"deny"}
    with pytest.raises(subprocess.CalledProcessError) as e:
        template_test(docker_image="fastfreeze-test-ff-installed", deny=deny, stderr=subprocess.PIPE)
    assert "Cannot ptrace siblings" in e.value.stderr

def test_show_install_error():
    deny={"user_namespace":"deny"}
    with pytest.raises(subprocess.CalledProcessError) as e:
        template_test(deny=deny, stderr=subprocess.PIPE)
    assert "Use `fastfreeze install`" in e.value.stderr

def test_with_namespaces():
    template_test()

def test_privileges():
    def detect_privileges(deny={}):
        respawn_docker_container(deny=deny)

        ff_run_proc = spawn_docker_exec([
                "fastfreeze", "run",
                "--image-url", f"{TEST_DIR}/test-image",
                "--no-restore", "-vv", "true"
            ], stderr=subprocess.PIPE)
        _, stderr = ff_run_proc.communicate()
        stderr = stderr.decode()
        match = re.search(r'Privileges {(.*?)}', stderr, re.DOTALL)
        assert match, "Privileges not detected"
        detected_privileges = match.group(1)
        p = {}
        for line in detected_privileges.splitlines():
            m = re.search(r'([^ :]*): (true|false)', line)
            if m:
                p[m.group(1)] = m.group(2) == 'true'
        return p

    p = detect_privileges()
    assert p['has_user_namespace']
    assert p['has_local_cap_sys_admin']
    assert p['has_time_namespace']
    assert p['has_mount_namespace']
    assert p['can_mount_bind']
    assert p['can_mount_devpts']
    assert p['has_pid_namespace']
    assert p['can_mount_proc']
    assert p['can_write_to_proc_ns_last_pid']
    assert p['can_ptrace_siblings']

    p = detect_privileges(deny={"user_namespace":"deny"})
    assert not p['has_user_namespace']

    p = detect_privileges(deny={"mount_namespace":"deny"})
    assert p['has_user_namespace']
    assert not p['has_mount_namespace']

    p = detect_privileges(deny={"pid_namespace":"deny"})
    assert p['has_user_namespace']
    assert not p['has_pid_namespace']

    p = detect_privileges(deny={"time_namespace":"deny"})
    assert p['has_user_namespace']
    assert not p['has_time_namespace']

    p = detect_privileges(deny={"ptrace":"deny"})
    assert not p['can_ptrace_siblings']


#def test_no_mount():
#    profile_path = write_seccomp_profile(has_mount_namespace=False)
#    docker_args = ["--security-opt", f"seccomp={profile_path}"]
#    docker_image = "fastfreeze-test"
#    template_test(docker_args, docker_image)
