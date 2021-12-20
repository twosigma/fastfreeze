from docker import respawn_docker_container
from common import * # '*' is important, otherwise before_* hooks don't run
import re

def test_docker_privileges():
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

    p = detect_privileges(deny={"mount_bind":"deny"})
    assert p['has_mount_namespace']
    assert not p['can_mount_bind']

    p = detect_privileges(deny={"mount_proc":"deny"})
    assert p['has_pid_namespace']
    assert p['can_mount_bind']
    assert not p['can_mount_proc']

###########################

def test_with_full_privileges_without_install():
    template_test()

def test_with_full_privs_with_install():
    template_test(docker_image="fastfreeze-test-ff-installed")

def test_no_user_namespace():
    # ptrace scope needs to be relaxed when we can't use user namespaces
    set_yama_ptrace_scope(0)
    deny={"user_namespace":"deny"}
    template_test(docker_image="fastfreeze-test-ff-installed", deny=deny)

def test_no_ptrace1():
    set_yama_ptrace_scope(0)
    deny={"ptrace":"deny"}
    template_test(fails_with="Cannot ptrace siblings",
        docker_image="fastfreeze-test-ff-installed", deny=deny)

def test_no_ptrace2():
    # Verify that we need set_yama_ptrace_scope(0) when we have no user user namespaces
    deny={"user_namespace":"deny"}
    template_test(fails_with="Cannot ptrace siblings",
        docker_image="fastfreeze-test-ff-installed", deny=deny)

def test_no_user_namespace_without_install():
    set_yama_ptrace_scope(0)
    deny={"user_namespace":"deny"}
    template_test(fails_with="Use `fastfreeze install`", deny=deny)

def test_no_mount_bind():
    deny={"mount_bind":"deny"}
    template_test(deny=deny)

def test_no_mount_proc():
    deny={"mount_proc":"deny"}
    template_test(deny=deny)

def test_no_pid_namespace():
    deny={"pid_namespace":"deny"}
    template_test(deny=deny)
