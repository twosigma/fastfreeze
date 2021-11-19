import subprocess
from datetime import datetime 
import time
import sys

def wait(fn, timeout=10):
    start_time = datetime.now()
    while True:
        if fn():
            return
        if (datetime.now()-start_time).seconds > timeout:
            raise RuntimeError("Timeout exceeded")
        time.sleep(0.1)

def eprint(line, color=None):
    #   Black      0;30       Dark Gray    1;30
    #   Red        0;31       Bold Red     1;31
    #   Green      0;32       Bold Green   1;32
    #   Yellow     0;33       Bold Yellow  1;33
    #   Blue       0;34       Bold Blue    1;34
    #   Purple     0;35       Bold Purple  1;35
    #   Cyan       0;36       Bold Cyan    1;36
    #   Light Gray 0;37       White        1;37

    # Can't test is sys.stderr.isattr() because pytest captures it, and we can't
    # even do it before tests start. stderr capture is done super early.
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
        stdout = stdout.decode()
        sys.stdout.write(stdout)
    if stderr is not None:
        stderr = stderr.decode()
        sys.stderr.write(stderr)
    return (stdout, stderr)

def flatten(l):
    return [item for sublist in l for item in sublist]
