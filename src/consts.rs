//  Copyright 2020 Two Sigma Investments, LP.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

use std::{
    time::Instant,
    path::PathBuf,
};
use crate::util::{
    gen_random_alphanum_string,
    get_home_dir,
};

// This file gathers all fastfreeze hard-coded settings

/// The image version must be bumped when libvirttime or libvirtcpuid change,
/// or when the `ImageManifest` format changes.
pub const CURRENT_IMG_VERSION: &str = "2021-03-12";

// We compute the paths at runtime. It improves readability compared to using
// macros at compile time.
lazy_static! {
    // We pick /var/tmp/fastfreeze for our directory and not /tmp because we place the
    // original ELF loader there (see libvirtcpuid). We want this to persist across reboot.
    // Also, /tmp is sometimes mounted with tmpfs, and that would be bad for us.
    // We need to pick a writable place, that can be hard-coded (the ELF loader
    // needs the absolute path at compile time).
    pub static ref FF_DIR: PathBuf             = PathBuf::from("/var/tmp/fastfreeze");
    pub static ref NO_PRESERVE_FF_DIR: PathBuf = FF_DIR.join("run");

    pub static ref APP_CONFIG_PATH: PathBuf  = FF_DIR.join("app-config.json");
    pub static ref FF_LOG_DIR: PathBuf       = FF_DIR.join("logs");

    // XXX When changing any of the `LD` paths, libvirtcpuid must be recompiled
    // See variables set in dist/Makefile
    pub static ref LD_SYSTEM_PATH: PathBuf      = PathBuf::from("/lib64/ld-linux-x86-64.so.2");
    pub static ref LD_SYSTEM_ORIG_PATH: PathBuf = NO_PRESERVE_FF_DIR.join(
                                                      LD_SYSTEM_PATH.file_name().unwrap());
    // This path is not necessarily ideal for root users as apparmor needs to be configured to
    // whitelist this path. But for non-root users, it's best for doing kubernetes mounting.
    pub static ref LD_VIRTCPUID_PATH: PathBuf = NO_PRESERVE_FF_DIR.join("ld-virtcpuid.so");
    pub static ref LIBVIRTCPUID_PATH: PathBuf = NO_PRESERVE_FF_DIR.join("libvirtcpuid.so");
    pub static ref LIBVIRTTIME_PATH: PathBuf  = NO_PRESERVE_FF_DIR.join("libvirttime.so");

    pub static ref LD_INJECT_ENV_PATH: PathBuf  = FF_DIR.join("ld-inject.env");
    pub static ref VIRT_TIME_CONF_PATH: PathBuf = FF_DIR.join("virttime-conf.bin");

    pub static ref CRIU_SOCKET_DIR: PathBuf       = NO_PRESERVE_FF_DIR.clone();
    // XXX When changing this socket path, CRIU must be changed and recompiled.
    pub static ref NS_LAST_PID_SOCK_PATH: PathBuf = NO_PRESERVE_FF_DIR.join("set_ns_last_pid.sock");
    pub static ref LOCK_FILE_PATH: PathBuf        = NO_PRESERVE_FF_DIR.join("lock");

    // CONTAINERS_DIR holds container directories. Each is a private
    // /var/tmp/fastfreeze directory for a given container
    pub static ref CONTAINERS_DIR: PathBuf = PathBuf::from("/tmp/fastfreeze");
    // The following paths are valid once we mound bind the container dir onto FF_DIR.
    pub static ref CONTAINER_PID: PathBuf = NO_PRESERVE_FF_DIR.join("pid");
    pub static ref CONTAINER_PTY: PathBuf = NO_PRESERVE_FF_DIR.join("pty");
    pub static ref CONTAINER_APP_TMP: PathBuf = FF_DIR.join("tmp");

    pub static ref DEFAULT_IMAGE_DIR: PathBuf = get_home_dir().map(|h| h.join(".fastfreeze"))
        .expect("Failed to determine home directory. Please set $HOME.");
}

/// Arbitrary application PID. Has to be bigger than 300 due to the way we do PID control
pub const APP_ROOT_PID: i32 = 1000;

/// When storing images, we use this filename to store our manifest
pub const MANIFEST_FILE_NAME: &str = "manifest.json";

/// Number of seconds to wait for processes to respond to a SIGTERM before sending a SIGKILL
pub const KILL_GRACE_PERIOD_SECS: u64 = 3;

/// Exit code we return when encountering a fatal error.
/// We use 170 to distinguish from the application error codes.
pub const EXIT_CODE_FAILURE: u8 = 170;
/// Exit code to denote an error during restore. Meaning that passing --no-restore would help
/// running the application.
pub const EXIT_CODE_RESTORE_FAILURE: u8 = 171;

/// When a process is running, we keep its stderr buffered, so that when an error
/// comes, we can report the stderr in metrics. This constant indicates how many
/// lines we want to report. Typically, we'll get something useful with the last
/// 20 lines. Having too many lines makes error triage difficult.
pub const STDERR_TAIL_NUM_LINES: usize = 20;

/// The default encryption cipher for encrypting the image.
/// We can let users define it in the future.
pub const DEFAULT_ENCRYPTION_CIPHER: &str = "aes-256-cbc";

lazy_static! {
    /// The invocation ID is a random 6 digit alphanum string. It is is used in a few places:
    /// 1) The shard prefix name
    /// 2) The log file name
    /// 3) Emitting metrics
    pub static ref INVOCATION_ID: String = gen_random_alphanum_string(6);
}

/// Where libraries like libvirttime.so and libvirtcpuid.so are searched
/// in addition to LD_LIBRARY_PATH.
pub const LIB_SEARCH_PATHS: &[&str] = &["/lib64", "/usr/lib", "/usr/local/lib"];

pub const KB: usize = 1024;
pub const MB: usize = 1024*1024;
pub const GB: usize = 1024*1024*1024;

pub const PAGE_SIZE: usize = 4*KB;

lazy_static! {
    pub static ref START_TIME: Instant = Instant::now();
}
