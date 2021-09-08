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

mod time;
pub mod elf_loader;

use anyhow::Result;
use std::{
    env,
    collections::HashMap,
};
use serde::{Serialize, Deserialize};
use crate::{
    container,
};

pub use time::Nanos;

// Note that the virtualization config gets included in the AppConfig JSON.
// This is so that we can restore a compatible version of the environment.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    /// Whether we need to hijack the system ELF loader, either with a mount
    /// bind, or the symlink via `fastfreeze install`.
    pub hijack_elf_loader_via_ff_install: bool,
    pub hijack_elf_loader_via_mount_bind: bool,

    /// Whether we do userspace (true) or kernelspace (false) CLOCK_MONOTONIC
    /// time virtualization.
    pub use_libvirttime: bool,

    /// Whether we need CPUID virtualization (we need it when
    /// FF_APP_VIRT_CPUID_MASK is specified by the user.
    pub cpuid_mask: Option<String>,

    /// Whether the user has specified some FF_APP_INJECT_* variables.
    pub ff_app_inject_vars: HashMap<String, String>,
}

// In this module, we deal with virtualizing the CPUID and time that the
// application observes.
// For this, three libraries are in play:
// 1) /lib64/ld-linux-x86-64.so.2: The ELF system loader. We hijack it either
//    during the install command or via a mount bind. We replace it with the
//    libvirtcpuid loader. The loader provides two things:
//    a) It sets up CPUID virtualization before libc's loader runs. Using
//       LD_PRELOAD would be too late.
//       More details can be found at https://github.com/twosigma/libvirtcpuid
//    b) It provides a way to inject environement variables in any process that uses
//       the ELF loader (essentially all dynamically loaded binaries) reliably.
//       This is especially useful to force the LD_PRELOAD env variable to
//       libvirttime.so. Even if the application clean its environment, it
//       won't escape time virtualization.
// 2) libvirtcpuid.so: This library role is to harden the virtualization put in
//    place by the hijacked ELF loader. It protects the SIGSEGV handler and is
//    loaded in the application with an LD_PRELOAD directive.
// 3) libvirttime.so: This virtualizes CLOCK_MONOTONIC for the application. 
//    It is loaded via LD_PRELOAD.
//    More details can be found at https://github.com/twosigma/libvirttime.

fn get_cpuid_mask() -> Option<String> {
    env::var_os("FF_APP_VIRT_CPUID_MASK")
        .filter(|v| !v.is_empty())
        .map(|v| v.into_string())
        .transpose()
        .expect("FF_APP_VIRT_CPUID_MASK is not UTF8")
}

fn ff_app_inject_vars() -> HashMap<String, String> {
    env::vars()
        .filter_map(|(k,v)| k.strip_prefix("FF_APP_INJECT_")
            .map(|subk| (subk.into(),v)))
        .collect()
}

/// Returns what needs to be virtualized via userspace trickeries.
/// Returns an error if we cannot do the necessary trickeries given the
/// current privileges.
pub fn get_required_virtualization(p: &container::Privileges) -> Result<Config> {
    let can_hijack_elf_loader = p.can_mount_bind || p.ff_installed;

    let use_libvirttime = !p.has_time_namespace;

    let cpuid_mask = get_cpuid_mask();
    let has_cpuid_mask = cpuid_mask.is_some();

    let ff_app_inject_vars = ff_app_inject_vars();
    let has_ff_app_inject_vars = !ff_app_inject_vars.is_empty();

    // We need the ELF loader to force loading of libvirttime.so reliably,
    // and do CPUID virtualization before libc loads.

    ensure!(can_hijack_elf_loader || !has_cpuid_mask,
        "Cannot do CPUID virtualization (FF_APP_VIRT_CPUID_MASK is set) because `mount --bind` fails. \
         Use `fastfreeze install` first, or provide mount namespace privileges");

    ensure!(can_hijack_elf_loader || !use_libvirttime,
        "Cannot do time virtualization neither in kernelspace nor userspace. \
         Use `fastfreeze install` first, or provide mount namespace privileges");

    ensure!(can_hijack_elf_loader || !has_ff_app_inject_vars,
        "Cannot do reliably inject env vars {:?}. \
         Use `fastfreeze install` first, or provide mount namespace privileges",
        ff_app_inject_vars.iter().map(|(k,v)| format!("FF_APP_INJECT_{}={}", k, v)).collect::<Vec<_>>());

    let hijack_elf_loader = has_cpuid_mask || use_libvirttime || has_ff_app_inject_vars;

    let hijack_elf_loader_via_ff_install = hijack_elf_loader && p.ff_installed;
    let hijack_elf_loader_via_mount_bind = hijack_elf_loader && !p.ff_installed;

    Ok(Config {
        hijack_elf_loader_via_ff_install,
        hijack_elf_loader_via_mount_bind,
        use_libvirttime,
        cpuid_mask,
        ff_app_inject_vars,
    })
}

pub fn ensure_sufficient_privileges_for_restore(config: &Config, p: &container::Privileges) -> Result<()> {
    let reason_why_elf_loader_is_needed = || {
        let mut reasons = vec![];
        if config.cpuid_mask.is_some() {
            reasons.push("CPUID is virtualized");
        }
        if config.use_libvirttime {
            reasons.push("time is virtualized in userspace");
        }
        if !config.ff_app_inject_vars.is_empty() {
            reasons.push("FF_APP_INJECT_* variables are in use");
        }
        reasons.join(", ")
    };

    ensure!(!config.hijack_elf_loader_via_ff_install || p.ff_installed,
        "The application was started on a host where `fastfreeze install` was used. \
         This host needs to be identically configured. \
         This is needed because {}", reason_why_elf_loader_is_needed());

    ensure!(!config.hijack_elf_loader_via_mount_bind || p.can_mount_bind,
        "The application was started on a host where `mount --bind` was used to hijack the ELF loader. \
         This host needs to be identically configured, but we are unable to use `mount --bind`. \
         This is needed because {}", reason_why_elf_loader_is_needed());

    Ok(())
}

/// Enable virtualization for a new application that we are running from scratch
/// Its monotonic clock is set to 0s.
pub fn enable_for_the_first_time(config: &Config) -> Result<()> {
    if config.use_libvirttime {
        time::ConfigPath::default().write_intial()?;
    } else {
        time::create_time_namespace(0)?;
    }

    elf_loader::configure_elf_loader(config)?;
    elf_loader::hijack_elf_loader(config)?;

    Ok(())
}

pub fn enable_for_restore(config: &Config, app_clock: time::Nanos) -> Result<()> {
    if config.use_libvirttime {
        time::ConfigPath::default().adjust_timespecs(app_clock)?;
    } else {
        time::create_time_namespace(app_clock)?;
    }

    // No need to configure the ELF loader, the config has been restored part of
    // the checkpoint image
    elf_loader::hijack_elf_loader(config)?;

    Ok(())
}

pub fn get_current_app_clock(config: &Config) -> Result<time::Nanos> {
    if config.use_libvirttime {
        time::ConfigPath::default().read_current_app_clock()
    } else {
        time::read_current_app_clock_in_its_time_namespace()
    }
}
