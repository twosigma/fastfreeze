import subprocess
from datetime import datetime 
import time
import os
import sys

# TODO rename FF_METRICS_RECORDER to FF_METRICS_CMD
# TODO test metrics
# TODO test encryption
# TODO test pretty much all the CLI options

TMP_DIR="/tmp/ff-test-images"

def eprint(line, color=None):
    #   Black      0;30       Dark Gray    1;30
    #   Red        0;31       Bold Red     1;31
    #   Green      0;32       Bold Green   1;32
    #   Yellow     0;33       Bold Yellow  1;33
    #   Blue       0;34       Bold Blue    1;34
    #   Purple     0;35       Bold Purple  1;35
    #   Cyan       0;36       Bold Cyan    1;36
    #   Light Gray 0;37       White        1;37
    if color:
        line = f'\033[{color}m{line}\033[00m'
    print(line, file=sys.stderr)

def human_subprocess_args(args):
    if not isinstance(args, list):
        return args
    def maybe_quote(a):
        if not ' ' in a:
            return a
        return f"'{a}'"
    return " ".join([maybe_quote(a) for a in args])

def print_cmd(args):
    eprint(f"+ {human_subprocess_args(args)}")

def subprocess_Popen(args, **kwargs):
    print_cmd(args)
    return subprocess.Popen(args, **kwargs)

def subprocess_run(args, **kwargs):
    print_cmd(args)
    if 'check' not in kwargs:
        kwargs['check'] = True
    return subprocess.run(args, **kwargs)

# Surprisingly, check_returncode() is implemented on subprocess.run(), but not
# subprocess.Popen(). So we'll make our own.
def check_returncode(p):
    ret = p.poll()
    if ret is not None and ret != 0:
        cmd = human_subprocess_args(p.args)
        stdout, stderr = subprocess_communicate(p)
        raise subprocess.CalledProcessError(returncode=p.returncode, cmd=cmd,
                                            stderr=stderr, output=stdout)

def subprocess_communicate(p, **kwargs):
    stdout, stderr = p.communicate(**kwargs)
    if stdout is not None:
        stdout = stdout.decode('utf8')
    if stderr is not None:
        stderr = stderr.decode('utf8')
    return (stdout, stderr)

def respawn_docker_container(docker_args=[], docker_image="fastfreeze-test:latest"):
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
        "--mount", f"type=bind,source={TMP_DIR},target={TMP_DIR}",
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
    p.communicate()
    check_returncode(p)

def docker_kill_container():
    subprocess_run(["docker", "kill", "ff"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def cleanup_image_dir():
    subprocess_run(["sudo", "rm", "-rf", TMP_DIR])
    subprocess_run(["mkdir", "-p", TMP_DIR])
    # /tmp-like permission as docker may run as user=nobody and write to TMP_DIR
    subprocess_run(["chmod", "1777", TMP_DIR])

def set_yama_ptrace_scope(value):
    cmd = f"echo {value} > /proc/sys/kernel/yama/ptrace_scope"
    subprocess_run(["sudo", "bash", "-c", cmd])

def set_pid_max(value):
    cmd = f"echo {value} > /proc/sys/kernel/pid_max"
    subprocess_run(["sudo", "bash", "-c", cmd])

def wait(fn, timeout=10):
    start_time = datetime.now()
    while True:
        if fn():
            return
        if (datetime.now()-start_time).seconds > timeout:
            raise RuntimeError("Timeout exceeded")
        time.sleep(0.1)
