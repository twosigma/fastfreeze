from util import *
import pytest

TEST_DIR="/tmp/ff-test"

@pytest.fixture(scope="module", autouse=True)
def before_all_tests():
    set_pid_max(10000)
    register_app_armor_profile()

@pytest.fixture(autouse=True)
def before_each_test():
    cleanup_test_dir()
    set_yama_ptrace_scope(1)

def register_app_armor_profile():
    profile = "profile none flags=(attach_disconnected) { \
        capability, network, mount, remount, umount, \
        pivot_root, ptrace, signal, dbus, unix, file, }"
    subprocess_run(["sudo", "apparmor_parser", "--replace"],
        input=profile, encoding='ascii')

def write_seccomp_profile_inner(profile):
    profile_path = f"{TEST_DIR}/seccomp.json"
    with open(profile_path, 'w') as f:
        json.dump(profile, f)
    return profile_path

def write_seccomp_profile(deny={}):
    profile = {
        "defaultAction": "SCMP_ACT_ALLOW",
        "defaultErrnoRet": 1,
        "syscalls": [],
    }

    def syscall_filter(name):
        filter = {
            "names": [name],
            "action": "SCMP_ACT_ERRNO",
        }
        profile["syscalls"].append(filter)

    def unshare_filter(unshare_arg):
        filter = {
            "names": ["unshare"],
            "action": "SCMP_ACT_ERRNO",
            "args": [{
                "index": 0,
                "value": unshare_arg,
                "valueTwo": unshare_arg,
                "op": "SCMP_CMP_MASKED_EQ"
            }]
        }
        profile["syscalls"].append(filter)

    if deny.pop("user_namespace", None):
        CLONE_NEWUSER = 0x10000000
        unshare_filter(CLONE_NEWUSER)
    if deny.pop("mount_namespace", None):
        CLONE_NEWNS = 0x00020000
        unshare_filter(CLONE_NEWNS)
    if deny.pop("pid_namespace", None):
        CLONE_NEWPID = 0x20000000
        unshare_filter(CLONE_NEWPID)
    if deny.pop("time_namespace", None):
        CLONE_NEWTIME = 0x00000080
        unshare_filter(CLONE_NEWTIME)

    if deny.pop("ptrace", None):
        syscall_filter("ptrace")

    return write_seccomp_profile_inner(profile)

def set_yama_ptrace_scope(value):
    cmd = f"echo {value} > /proc/sys/kernel/yama/ptrace_scope"
    subprocess_run(["sudo", "bash", "-c", cmd])

# permissions is to permit all by default, setting something to false will
# remove the permission.
# (it's contrary to typical security settings where things need to be
# whitelisted, but that's because we are not trying to do something secure. We
# are doing some testing)
def respawn_docker_container(docker_args=[], docker_image="fastfreeze-test", deny={}):
    if not deny:
        docker_args = docker_args + ["--privileged"]
    else:
        # We make a clone because we modify it.
        deny = {**deny}
        profile_path = write_seccomp_profile(deny)
        docker_args = docker_args + ["--security-opt", f"seccomp={profile_path}",
                                     "--security-opt", "apparmor=none"]
        assert not list(deny.keys())
        subprocess_run(["cat", profile_path])

    docker_kill_container()

    args = [
        "docker", "run",
        "--rm",
        "--user", "nobody",
        "--env", "RUST_BACKTRACE=1",
        "--detach",
        "--init",
        *docker_args,
        "--name", "ff",
        "--mount", f"type=bind,source={TEST_DIR},target={TEST_DIR}",
        docker_image,
        "sleep", "1d",
    ]
    return subprocess_run(args)

def spawn_docker_exec(cmd, docker_args=[], **kwargs):
    args = [
        "docker", "exec",
        "--env", "RUST_BACKTRACE=1",
        *docker_args,
        "ff",
        *cmd,
    ]
    return subprocess_Popen(args, **kwargs)

def docker_exec(cmd, docker_args=[], **kwargs):
    p = spawn_docker_exec(cmd, docker_args, **kwargs)
    subprocess_communicate(p)
    check_returncode(p)

def docker_kill_container():
    subprocess_run(["docker", "kill", "ff"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def cleanup_test_dir():
    subprocess_run(["sudo", "rm", "-rf", TEST_DIR])
    subprocess_run(["mkdir", "-p", TEST_DIR])
    # /tmp-like permission as docker may run as user=nobody and write to TMP_DIR
    subprocess_run(["chmod", "1777", TEST_DIR])

def set_pid_max(value):
    cmd = f"echo {value} > /proc/sys/kernel/pid_max"
    subprocess_run(["sudo", "bash", "-c", cmd])
