![Build](https://github.com/twosigma/fastfreeze/workflows/Build/badge.svg)

<p align="center">
  <img
    src="https://github.com/twosigma/fastfreeze/raw/master/.github/fastfreeze-logo.png"
    width="180px"
  />
</p>

## Introduction

_FastFreeze_ enables checkpoint/restore for applications running in Linux
containers. It uploads/downloads checkpoint images to AWS S3 and Google Storage,
provides a friendly CLI to job systems, and does not require elevated privileges
(such as `CAP_SYS_ADMIN`).

The primary use-case of FastFreeze is to make long running and resource
intensive applications resilient to failure. This is useful for a variety of
reasons such as reducing compute waste, or lowering application completion time.
This makes Google's preemptible VM and Amazon Spot VM offerings more attractive.
We are exploring other use-cases such as JVM memory ballooning, warm-boots, and
jupyter integration.

FastFreeze is powered by the [CRIU](https://criu.org/) engine.

### Usage in a nutshell

1. **Start** the application via FastFreeze with the `run` command in an empty
   Linux container (e.g., Kuebrnetes, Docker).

   ```
   fastfreeze run --image-url s3://fastfreeze-images/job-1234.ff -- app.sh [args...]
   ```

2. **Checkpoint** the application with the `checkpoint` command.
   This persists the state of the application into the AWS S3 location we
   provided at step 1. The application is terminated upon successful checkpoint.

   ```
   fastfreeze checkpoint
   ```

3. **Restore** the application by running is the same command as step 1,
   possibly on another machine. The `run` command checks if the image is
   present. If so, it restores the application. If not, it runs the application
   from scratch. This makes FastFreeze ideal to integrate with existing job
   systems that retry commands until the job succeeds.


   ```
   # same as step 1
   ```

## Features

FastFreeze includes the following high-level features:

* **Unprivileged**: FastFreeze does not need privileges like `CAP_SYS_ADMIN` to
  operate. We use a modified version of CRIU to accomplish this. In addition, we
  use [set_ns_last_pid](https://github.com/twosigma/set_ns_last_pid) to control
  PIDs by cycling through PIDs at a rate of 100,000/s by essentially doing a
  fork bomb, until we reach the PID that we desire.

* **Fast**: FastFreeze uses
  [criu-image-streamer](https://github.com/checkpoint-restore/criu-image-streamer)
  to perform fast checkpointings at speed of up to 15GB/s, given enough CPU and
  network bandwidth. This makes Google's preemptible VM and Amazon Spot VM
  offerings more attractive. FastFreeze can checkpoint and evacuate large
  applications (e.g., using 30GB of memory) within the tight eviction deadlines
  (~30secs).

* **Low overhead**: FastFreeze needs less than 100MB of memory to perform a
  checkpoint or a restore. This memory headroom must be reserved in the
  container in addition to what the application uses. Note that the standard S3
  and GCS uploaders (`aws s3` and `gsutil`) tend to use a lot of memory (500MB)
  due to the fact that they are written in Python and use large buffers. In the
  future, we plan to open-source our custom uploaders that can be used with
  FastFreeze.

* **Compression**: Checkpoint images can be compressed on the fly with lz4 or
  zstd. Setting the `--cpu-budget` option when checkpointing provides ways to
  control the compression algorithm. Compression is parallelized for optimal
  performance.

* **Encryption**: Checkpoint images can be encypted on the fly with openssl.
  Setting the `--passphrase-file` option enables encryption using AES-256-CBC.

* **CPUID virtualization**: FastFreeze enables CPU virtualization with
  [libvirtcpuid](https://github.com/twosigma/libvirtcpuid). This enables the
  migration of applications within a heterogeneous datacenter. For example,
  starting an application on a machine that supports transactional memory can
  be migrated to a host that does not.

* **Time virtualization**: FastFreeze implements time virtualization in
  userspace to offset the `CLOCK_MONOTONIC` when migrating to other machines
  with [libvirttime](https://github.com/twosigma/libvirttime).
  This feature is crucial for Java programs. Note there is a time namespace
  available in the kernel, but FastFreeze does not use it as it requires
  `CAP_SYS_ADMIN`.

* **File system**: FastFreeze checkpoints and restore the files used by the
  application such as logs, and other temporary files. These files are not
  automatically detected, but rather, the user must specify the paths (files or
  directories) that must be preserved via the `--preserve-path` option.

* **Metrics**: FastFreeze can be configured to emit metrics to an external
  service to collect checkpoint/restore stats. This is helpful to track the SLA
  of FastFreeze.

### Non-root limitations

FastFreeze does not use privileged operations. This creates the following drawbacks:

* FastFreeze must run within a Linux container (e.g., Kubernetes, Docker). This
  guarantees that there are no PID conflicts. The container image must remain
  unchanged when migrating an application to a different container.

* The network connections are dropped upon restore. We rely on the application
  to be tolerant to network failures and reconnect to needed services.

* The `/proc/self/exe` symlink is not restored and will point to the criu binary.
  When using gdb to attach to a restored program, one must pass the real
  executable path to gdb as such: `gdb -p PID /path/to/exe`.

* Controlling PIDs without `CAP_SYS_ADMIN` can be slow if
  `/proc/sys/kernel/pid_max` is high. We recommend setting a value lower than
  100,000.

* Memory mapped files that have been deleted are not supported.

* As FastFreeze assumes operating within a Linux container, it does not
  checkpoint/restore cgroups, seccomp, and user capabilities. We also do not
  support System V IPC.
  Create an [issue](https://github.com/twosigma/fastfreeze/issues/new) if you
  need IPC support.

### Supported Applications

FastFreeze supports most Linux applications, with some restrictions:

* GPUs and external devices are not supported.

* Applications that rely on host-dependent environment variables (like hostname,
  or job id) may have issues when migrated to a new host. Avoid relying on such
  variables, or caching host-dependent information.

* Applications that use ptrace cannot be checkpointed (e.g., running under
  `strace`).

* Due to CPUID virtualization, Only x86 64-bits applications running with GNU
  libc are supported. In practice, that means no musl libc, so no alpine docker.

* Secure binaries are not supported. For example, an application that runs a
  script with `sudo` is a problem.

* On some systems, apparmor can prevent the execution of certain application
  such as `man` because we relocate the system ld.so at `/var/fastfreeze/run`
  which may not be in the white-listed path of executable mmap files. This is
  not an issue in practice.

* FastFreeze only supports a single application execution at a time within a
  container. An application can nevertheless be comprised of many processes and
  threads. To run two instances of FastFreeze, one must use two separate
  containers.

### Non-features

* Checkpoint images are not managed by FastFreeze. Pruning old images is not in
  the scope of FastFreeze.

## Usage

### Installation

FastFreeze is distributed in a self-contained 4MB package that needs to be
extracted in `/opt/fastfreeze`.

The following shows an example of the installation of FastFreeze in a Debian
Docker image.

```dockerfile
FROM debian:10

RUN apt-get update
RUN apt-get install -y curl xz-utils libcap2-bin

RUN set -ex; \
  curl -SL https://github.com/twosigma/fastfreeze/releases/download/v1.1.0/fastfreeze-1.1.0.tar.xz | \
    tar xJf - -C /opt; \
  ln -s /opt/fastfreeze/fastfreeze_wrapper.sh /usr/local/bin/fastfreeze; \
  fastfreeze install; \
  setcap cap_sys_ptrace+eip /opt/fastfreeze/criu
```

The `install` command overrides the system loader `/lib64/ld-linux-x86-64.so.2`,
and creates `/var/fastfreeze` where files such as logs are kept. Note that
replacing the system loader is useful even when not doing CPUID virtualization.
It facilitates the injection of the time virtualiation library into all processes.

The `setcap` command adds the `CAP_SYS_PTRACE` capability to CRIU.
This may or may not be needed depending on the yama configuration
`/proc/sys/kernel/yama/ptrace_scope` (see `man ptrace(2)`), or if Kubernetes is
configured with `CAP_SYS_PTRACE` as ambiant capability.

### Tutorial

You may try out FastFreeze with the following:

```bash
# First, save the previously suggested Dockerfile from the Installation section
# in the current directory
$ cat > Dockerfile

# Then, build the docker image
$ docker build . -t fastfreeze

# 1) Run the application for the first time
$ docker run \
  --rm -it \
  --user nobody \
  --cap-add=cap_sys_ptrace \
  --name ff \
  --mount type=bind,source=/tmp,target=/tmp \
  fastfreeze:latest \
  fastfreeze run --image-url file:/tmp/ff-test -- \
    bash -c 'for i in $(seq 100); do echo $i; sleep 1; done'

# The application is running. We should see on the terminal:
#   [ff.run] (0.001s) Time is Sat, 15 Aug 2020 05:21:41 +0000
#   [ff.run] (0.001s) Host is 44f6ce3d5b4a
#   [ff.run] (0.001s) Invocation ID is Jg9qyV
#   [ff.run] (0.012s) Fetching image manifest for file:/tmp/ff-test
#   [ff.run] (0.014s) Image manifest not found, running application from scratch
#   [ff.run] (0.030s) Application is ready, started from scratch
#   1
#   2
#   3
#   4

# 2) In another terminal, we invoke the checkpoint command
$ docker exec ff fastfreeze checkpoint

# We should see:
#   [ff.checkpoint] (0.000s) Time is Sat, 15 Aug 2020 05:21:54 +0000
#   [ff.checkpoint] (0.000s) Host is 44f6ce3d5b4a
#   [ff.checkpoint] (0.000s) Invocation ID is aaNN7y
#   [ff.checkpoint] (0.000s) Checkpointing application to file:/tmp/ff-test (num_shards=4 compressor=Lz4 prefix=aaNN7y)
#   tar: Removing leading `/' from member names
#   [ff.checkpoint] (0.014s) Uncompressed image size is 1 MiB, rate: 132 MiB/s
#   [ff.checkpoint] (0.017s) Checkpoint to file:/tmp/ff-test complete. Took 0.0s

# The first terminal should show:
#   [ff.run] (13.012s) Exiting with exit_code=137: Application caught fatal signal SIGKILL
#
# The application is now checkpointed. We can inspect the image in /tmp/ff-test
# We see that the image is split into 4 different pieces. This split is
# used to parallelize checkpointing, improving performance.
$ ls -lh /tmp/ff-test

#   total 116K
#   -rw-r--r-- 1 nobody nogroup 22K Aug 15 05:21 aaNN7y-1.ffs
#   -rw-r--r-- 1 nobody nogroup 19K Aug 15 05:21 aaNN7y-2.ffs
#   -rw-r--r-- 1 nobody nogroup 42K Aug 15 05:21 aaNN7y-3.ffs
#   -rw-r--r-- 1 nobody nogroup 23K Aug 15 05:21 aaNN7y-4.ffs
#   -rw-r--r-- 1 nobody nogroup  82 Aug 15 05:21 manifest.json

# 3) We restore the application by running the same command as in 1)
$ docker run \
  --rm -it \
  --user nobody \
  --cap-add=cap_sys_ptrace \
  --name ff \
  --mount type=bind,source=/tmp,target=/tmp \
  fastfreeze:latest \
  fastfreeze run --image-url file:/tmp/ff-test -- \
    bash -c 'for i in $(seq 100); do echo $i; sleep 1; done'

# We see in the terminal;
#  [ff.run] (0.000s) Time is Sat, 15 Aug 2020 05:29:53 +0000
#  [ff.run] (0.000s) Host is 4259e670e092
#  [ff.run] (0.000s) Invocation ID is V0qRYI
#  [ff.run] (0.015s) Fetching image manifest for file:/tmp/ff-test
#  [ff.run] (0.017s) Restoring application
#  [ff.run] (0.126s) Uncompressed image size is 1 MiB, rate: 134 MiB/s
#  [ff.run] (0.157s) Application is ready, restore took 0.2s
#  5
#  6
#  7
#  8
```

In this example, we used the local file system to store the checkpoint image,
but in practice one would use something like AWS S3, or GCS.

## Detailed Usage

Below is shown a synopsis of the FastFreeze available commands.

```
USAGE:
    fastfreeze <SUBCOMMAND>

SUBCOMMANDS:
    run           Run application. If a checkpoint image exists, the application is
                  restored. Otherwise, the application is run from scratch
    checkpoint    Perform a checkpoint of the running application
    extract       Extract a FastFreeze image to local disk
    wait          Wait for checkpoint or restore to finish
    install       Install FastFreeze in the specified directory
```

### run

Run application. If a checkpoint image exists, the application is restored.
Otherwise, the application is run from scratch

```
USAGE:
    fastfreeze run [OPTIONS] --image-url <url> [--] [app-args]...

OPTIONS:
        --image-url <url>          Image URL. S3, GCS and local filesystem are supported:
                                    * s3://bucket_name/image_path
                                    * gs://bucket_name/image_path
                                    * file:image_path
        --on-app-ready <cmd>       Shell command to run once the application is running
        --passphrase-file <file>   Provide a file containing the passphrase to be used for encrypting or
                                   decrypting the image. For security concerns, using a ramdisk like
                                   /dev/shm to store the passphrase file is preferable
        --preserve-path <path>...  Dir/file to include in the checkpoint image.
                                   May be specified multiple times.
                                   Multiple paths can also be specified colon separated
        --no-restore               Always run the app from scratch. Useful to ignore a faulty image
        --allow-bad-image-version  Allow restoring of images that don't match the version we expect
        --leave-stopped            Leave application stopped after restore, useful for debugging.
                                   Has no effect when running the app from scratch
    -v, --verbose                  Verbosity. Can be repeated

ARGS:
    <app-args>...    Application arguments, used when running the app from scratch. Ignored during restore

ENVS:
    FF_APP_PATH               The PATH to use for the application
    FF_APP_LD_LIBRARY_PATH    The LD_LIBRARY_PATH to use for the application
    FF_APP_VIRT_CPUID_MASK    The CPUID mask to use. See libvirtcpuid documentation for more details
    FF_APP_INJECT_<VAR_NAME>  Additional environment variables to inject to the application and its children.
                              For example, FF_APP_INJECT_LD_PRELOAD=/opt/lib/libx.so
    FF_METRICS_RECORDER       When specified, FastFreeze invokes the specified program to report metrics.
                              The metrics are formatted in JSON and passed as first argument
    CRIU_OPTS                 Additional arguments to pass to CRIU, whitespace separated
    S3_CMD                    Command to access AWS S3. Defaults to 'aws s3'
    GS_CMD                    Command to access Google Storage3. Defaults to 'gcs_streamer'

EXIT CODES:
    171          A failure happened during restore, or while fetching the image manifest.
                 Retrying with --no-restore will avoid that failure
    170          A failure happened before the application was ready
    128+sig_nr   The application caught a fatal signal corresponding to `sig_nr`
    exit_code    The application exited with `exit_code`
```


### checkpoint

Perform a checkpoint of the running application

```
USAGE:
    fastfreeze checkpoint [OPTIONS]

OPTIONS:
        --leave-running            Leave application running after checkpoint
        --image-url <image-url>    Image URL, defaults to the value used during the run command
        --preserve-path <path>...  Dir/file to include in the image in addition to the ones specified during the
                                   run command. May be specified multiple times. Multiple paths can also be specified
                                   colon separated
        --num-shards <num-shards>  Level of parallelism. Split the image in multiple shards [default: 4]
        --cpu-budget <cpu-budget>  Amount of CPU at disposal. Possible values are [low, medium, high]. Currently,
                                   `low` skips compression, `medium` uses lz4, and high uses zstd [default: medium]
        --passphrase-file <file>   Enable image encryption. This points to a file containing a passphrase
                                   used to encrypt the image. The passphrase should contain at least 256
                                   bits of entropy

    -v, --verbose                  Verbosity. Can be repeated

ENVS:
    FF_METRICS_RECORDER  When specified, FastFreeze invokes the specified program to report metrics.
                         The metrics are formatted in JSON and passed as first argument
    CRIU_OPTS            Additional arguments to pass to CRIU, whitespace separated
    S3_CMD               Command to access AWS S3. Defaults to 'aws s3'
    GS_CMD               Command to access Google Storage3. Defaults to 'gcs_streamer'
```

### extract

Extract a FastFreeze image to local disk

```
USAGE:
    fastfreeze extract [OPTIONS] --image-url <image-url>

OPTIONS:
    -i, --image-url <image-url>      Image URL, which can also be a regular local path
    -o, --output-dir <output-dir>    Output directory where to extract the image.
                                     Defaults to the last path component of image-url
        --allow-bad-image-version    Allow restoring of images that don't match the version we expect
    --passphrase-file <file>         Provide a file containing the passphrase to be used for decrypting the image
    -v, --verbose                    Verbosity. Can be repeated

ENVS:
    S3_CMD   Command to access AWS S3. Defaults to 'aws s3'
    GS_CMD   Command to access Google Storage3. Defaults to 'gcs_streamer'
```

### wait

Wait for checkpoint or restore to finish

```
USAGE:
    fastfreeze wait [OPTIONS]

OPTIONS:
    -t, --timeout <timeout>    Fail after some specified number of seconds. Decimals are allowed
    -v, --verbose              Verbosity. Can be repeated
```


### install

Install FastFreeze, mostly to setup virtualization

```
USAGE:
    fastfreeze install [OPTIONS]

OPTIONS:
    -v, --verbose    Verbosity. Can be repeated
```


## Acknowledgments
* Author: Nicolas Viennot [@nviennot](https://github.com/nviennot)
* Tester: Hung Tan Tran [@hungtantran](https://github.com/hungtantran)
* Reviewer: Peter Burka [@pburka](https://github.com/pburka)
* Developed as a [Two Sigma Open Source](https://opensource.twosigma.com) initiative

License
-------

FastFreeze is licensed under the
[Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
