#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <err.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

static int (*dlsym_clock_gettime)(clockid_t, struct timespec*);

static void print_time() {
    struct timespec ts;
    int ret;

    ret = dlsym_clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret)
        err(1, "dlsym_clock_gettime failed");
    printf("lookup=dlsym tv_sec=%ld tv_nsec=%ld\n", ts.tv_sec, ts.tv_nsec);

    ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret)
        err(1, "clock_gettime_func failed");
    printf("lookup=regular tv_sec=%ld tv_nsec=%ld\n", ts.tv_sec, ts.tv_nsec);
}

static void pause_execution() {
    // We don't use SIGSTOP/SIGCONT to pause and resume. It can be messy to kill
    // the program when it is stopped, and the program running state be
    // tampered when restoring. We'll watch a file instead, it's more robust.

    const char *resume_path = getenv("RESUME_PATH");
    struct stat statbuf;
    if (resume_path) {
        fprintf(stderr, "Waiting for file %s to appear\n", resume_path);

        fflush(stdout);
        fflush(stderr);

        while (1) {
            if (stat(resume_path, &statbuf) == 0)
                break;
            if (errno != ENOENT)
                err(1, "stat failed");

            usleep(100000); // 0.1s

        }
        fprintf(stderr, "Resuming execution\n");
    } else {
        fprintf(stderr, "RESUME_PATH is not specified, skipping pause/resume\n");
    }
}

int main(int argc, const char *argv[])
{
    void* librt = dlopen("librt.so.1", RTLD_LAZY);
    if (librt == NULL)
        librt = dlopen("librt.so", RTLD_LAZY);
    if (librt == NULL)
        err(1, "no librt");

    dlsym_clock_gettime = dlsym(librt, "clock_gettime");
    if (dlsym_clock_gettime == NULL)
        err(1, "dlsym clock_gettime fail");

    print_time();
    // checkpoint/restore should happen during pause_execution()
    pause_execution();
    print_time();

    return 0;
}
