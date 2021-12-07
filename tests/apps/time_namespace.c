#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/wait.h>

#define _CLONE_NEWTIME 0x80

static void write_file(const char *path, const char *fmt, ...)
{
    va_list ap;
    FILE *f = fopen(path, "w");
    if (!f)
        err(1, "Failed to open file %s", path);

    va_start(ap, fmt);
    if (vfprintf(f, fmt, ap) < 0)
        err(1, "Failed to write to file %s", path);
    va_end(ap);

    if (fclose(f) < 0)
        err(1, "Failed to write to file %s", path);
}

static void create_user_namespace()
{
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER) < 0)
        err(1, "Failed to create user namespace");

    write_file("/proc/self/setgroups", "deny");
    write_file("/proc/self/uid_map", "0 %d 1", uid);
    write_file("/proc/self/gid_map", "0 %d 1", gid);
}

static void create_time_namespace(int monotonic_offset_secs)
{
    if (unshare(_CLONE_NEWTIME) < 0)
        err(1, "Failed to create time namespace");

    write_file("/proc/self/timens_offsets", "monotonic %d 0", monotonic_offset_secs);
}

static void exec_in_time_namespace(char *const app_cmd[], int monotonic_offset_secs)
{
    create_user_namespace();
    create_time_namespace(monotonic_offset_secs);

    pid_t pid = fork();

    if (pid < 0)
        err(1, "failed to fork");

    if (pid == 0) {
        execvp(app_cmd[0], app_cmd);
        err(1, "Failed to execve %s", app_cmd[0]);
    }

    int wstatus;
    if (waitpid(pid, &wstatus, 0) < 0)
        err(1, "Failed to wait on child pid=%d", pid);

    if (WIFEXITED(wstatus))
        exit(WEXITSTATUS(wstatus));
    if (WIFSIGNALED(wstatus))
        exit(128 + WTERMSIG(wstatus));

    errx(1, "no exit status");
}

int main(int argc, char *const argv[])
{
    if (argc < 3)
        errx(1, "usage: %s <monotonic_offset_secs> <app_cmd...>", argv[0]);

    int monotonic_offset_secs = atoll(argv[1]);
    char *const *app_cmd = &argv[2];

    exec_in_time_namespace(app_cmd, monotonic_offset_secs);
}
