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

pub mod time;

use anyhow::{Result, Context};
use std::{
    io::prelude::*,
    io::{BufRead, BufReader, BufWriter, Cursor},
    os::unix::ffi::OsStrExt,
    env,
    fs,
};
use crate::{
    consts::*,
    util::strip_prefix,
    process::{Command, Stdio, EnvVars},
};

// The application needs to be virtualized in aspects: CPUID and time.
// For this, three libraries are in play:
// 1) /lib64/ld-linux-x86-64.so.2: The ELF system loader. We hijack it during the
//    install command. We replace it with the libvirtcpuid loader. The loader
//    provides two things:
//    a) It sets up CPUID virtualization before libc's loader runs. Using
//       LD_PRELOAD would be too late.
//       More details can be found at https://github.com/twosigma/libvirtcpuid
//    b) It provides a way to inject environement variables in any process that uses
//       the ELF loader (essentially all dynamically loaded binaries). This is
//       especially useful to force the LD_PRELOAD env variable to applications, even
//       the one that try hard to clean up their environement.
//       Note: that's why we need libvirtcpuid, even if we don't need CPUID
//       virtualization.
// 2) libvirtcpuid.so: This library role is to harden the virtualization put in
//    place by the hijacked ELF loader. It protects the SIGSEGV handler and is
//    loaded in the application with an LD_PRELOAD directive.
// 3) libvirttime.so: This virtualizes CLOCK_MONOTONIC for the application. 
//    It is loaded via LD_PRELOAD.
//    More details can be found at https://github.com/twosigma/libvirttime.

fn env_for_virtualization() -> EnvVars {
    let mut env: EnvVars = EnvVars::new();
    let mut ld_preloads = vec![];

    // We always need time virtualization
    ld_preloads.push(LIBVIRTTIME_PATH.clone());
    env.insert("VIRT_TIME_CONF".into(), (&*VIRT_TIME_CONF_PATH).into());

    // But not always need CPUID virtualization
    if let Some(cpuid_mask) = env::var_os("FF_APP_VIRT_CPUID_MASK") {
        if !cpuid_mask.is_empty() {
            ld_preloads.push(LIBVIRTCPUID_PATH.clone());
            env.insert("VIRT_CPUID_MASK".into(), cpuid_mask);
        }
    }

    // Users can force env variables via FF_APP_INJECT_*
    for (key, value) in env::vars_os() {
        // The env var key is all ASCII, it's okay to use to_string_lossy()
        let key = key.to_string_lossy();
        if let Some(key) = strip_prefix(&key, "FF_APP_INJECT_") {
            if key == "LD_PRELOAD" {
                for path in env::split_paths(&value) {
                    ld_preloads.push(path);
                }
            } else {
                env.insert(key.into(), value);
            }
        }
    }

    // unwrap is okay here as we cannot possibly have a ":" in one of the ld_preload paths.
    env.insert("LD_PRELOAD".into(), env::join_paths(ld_preloads).unwrap());

    env
}

/// The system ELF loader interposition loads the LD_INJECT_ENV_PATH as
/// environment variable for all application on the system.
fn inject_env_system_wide(env: &EnvVars) -> Result<()> {
    || -> Result<_> {
        // These env variables are forced into any program
        // that do not have LD_ENV_DISABLE enabled.
        let mut ld_inject_file = BufWriter::new(
            fs::File::create(&*LD_INJECT_ENV_PATH)?);

        for (key, value) in env {
            // format!() would be nicer, but we need to work with OsString, not String.
            ld_inject_file.write_all(key.as_bytes())?;
            ld_inject_file.write_all(b"=")?;
            ld_inject_file.write_all(value.as_bytes())?;
            ld_inject_file.write_all(b"\n")?;
        }

        ld_inject_file.flush()?;

        Ok(())
    }().with_context(|| format!("Failed to create {}", LD_INJECT_ENV_PATH.display()))
}

fn ensure_system_wide_virtualization_is_enabled() -> Result<()> {
    // Check if applications are getting virtualization env injection via libvirtcpuid.
    let output = || -> Result<_> {
        Command::new(&["env"])
            .stdout(Stdio::piped())
            .spawn()?
            .wait_with_output()
            .and_then(|o| o.ensure_success().map(|_| o))
    }().context("Failed to run the `env` command")?;

    for line in BufReader::new(Cursor::new(output.stdout)).lines() {
        if line.unwrap_or_default().starts_with("VIRT_TIME_CONF=") {
            return Ok(());
        }
    }

    bail!("Applications can escape virtualization, creating hard to diagnose problems. \
           Run `fastfreeze install` to setup virtualization. \
           A kuberbetes volume may be needed to interpose the system ELF loader");
}

pub fn enable_system_wide_virtualization() -> Result<()> {
    let env = env_for_virtualization();
    inject_env_system_wide(&env)?;
    ensure_system_wide_virtualization_is_enabled()?;
    Ok(())
}

/// This function is called early on to disable the system wide time
/// virtualization on our process. (we need the real time)
/// It can call execve(). Note that logging is not setup yet.
pub fn disable_local_time_virtualization() -> Result<()> {
    if env::var_os("VIRT_TIME_CONF").is_some() {
        // We are currently executing with time virtualization enabled. This is
        // a problem when we try to get the real machine clock. To avoid this,
        // we re-exec ourselves with LD_ENV_DISABLE set, which prevents the
        // libvirtcpuid's loader from injecting env variables into our process.
        env::set_var("LD_ENV_DISABLE", "1");
        env::remove_var("VIRT_TIME_CONF");
        env::remove_var("LD_PRELOAD"); // libvirttime.so is in there, and needs to go.

        Command::new(env::args_os())
            .exec()
            .context("Failed to execve() ourselves to disable time virtualization")
    } else {
        // We are not virtualized, but our children should be.
        env::remove_var("LD_ENV_DISABLE");
        Ok(())
    }
}
