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

use anyhow::{Result, Context};
use std::{
    mem::{size_of, MaybeUninit},
    os::unix::io::AsRawFd,
    os::unix::fs::PermissionsExt,
    path::Path,
    io::prelude::*,
    io::SeekFrom,
    slice,
    fs,
};
use nix::unistd::{lseek, Whence};
#[cfg(not(test))]
use nix::{Error, errno::Errno};
use libc::timespec;
use crate::{
    consts::*,
    util::pwrite_all,
};

// This file contains logic to configure libvirttime. In a nutshell, libvirttime
// is used to virtualize the CLOCK_MONOTONIC values for the application. The
// library is configured via an external file that contains all the clock time
// offsets to be applied.
//
// The config file has the following format:
//    static struct virt_time_config {
//        struct timespec ts_offset;
//        struct timespec per_thread_ts[PID_MAX];
//    };
//
// There is a global time offset, and a per thread time offset. All must be
// adjusted when migrating an app from a machine to another.
//
// More details can be found at https://github.com/twosigma/libvirttime


// `PID_MAX` is defined in the kernel in include/linux/threads.h
// We don't read /proc/sys/kernel/pid_max because it can vary
// from machine to machine.
const PID_MAX: u32 = 4_194_304;
const NSEC_IN_SEC: Nanos = 1_000_000_000;

/// File position of virt_time_config.thread_confs[0]
const PID_0_FPOS: i64 = size_of::<timespec>() as i64;
/// sizeof(struct per_thread_conf)
const PROCESS_AREA_SIZE: usize = size_of::<timespec>();

/// We represent a `timespec` with the nanosecs as a i128. It's easier to do
/// computation with. `Duration` is not suitable for us as it lack support
/// underflowing substractions.
pub type Nanos = i128;

#[cfg(not(test))]
fn clock_gettime_monotonic() -> Nanos {
    let result = unsafe {
        let mut ts = MaybeUninit::<timespec>::uninit();
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) == 0 {
            Ok(Nanos::from_timespec(ts.assume_init()))
        } else {
            Err(Error::Sys(Errno::last()))
        }
    };

    result.expect("clock_gettime() failed")
}

#[cfg(test)]
fn clock_gettime_monotonic() -> Nanos {
    test::clock_gettime_mock()
}

trait NanosExt {
    fn to_timespec(self) -> timespec;
    fn from_timespec(ts: timespec) -> Self;
}

impl NanosExt for Nanos {
    fn to_timespec(self) -> timespec {
        let mut ts = timespec {
            tv_sec: (self / NSEC_IN_SEC) as i64,
            tv_nsec: (self % NSEC_IN_SEC) as i64,
        };

        // nsec should always be positive as the libvirttime code assumes nsec is between 0 and
        // NSEC_IN_SEC-1. See https://github.com/twosigma/libvirttime/blob/master/src/util.h#L48
        if ts.tv_nsec < 0 {
            ts.tv_sec -= 1;
            ts.tv_nsec += NSEC_IN_SEC as i64;
        }

        ts
    }

    fn from_timespec(ts: timespec) -> Self {
        ts.tv_sec as i128 * NSEC_IN_SEC + ts.tv_nsec as i128
    }
}

fn read_timespec<R: Read>(reader: &mut R) -> Result<Nanos> {
    unsafe {
        let mut ts = MaybeUninit::<timespec>::uninit();
        let mut buf = slice::from_raw_parts_mut(
            ts.as_mut_ptr() as *mut u8,
            size_of::<timespec>()
        );
        reader.read_exact(&mut buf)
            .context("Failed to read from the time config file")?;

        Ok(Nanos::from_timespec(ts.assume_init()))
    }
}

fn write_timespec_at(file: &fs::File, nanos: Nanos, fpos: i64) -> Result<()> {
    unsafe {
        let ts = nanos.to_timespec();
        let buf = slice::from_raw_parts(
            &ts as *const timespec as *const u8,
            size_of::<timespec>()
        );
        pwrite_all(file, &buf, fpos)
            .context("Failed to write to the time config file")?;
        Ok(())
    }
}

pub struct ConfigPath<'a> {
    path: &'a Path,
}

impl<'a> ConfigPath<'a> {
    pub fn new<S: AsRef<Path>>(path: &'a S) -> Self {
        // We don't open the config file at this point. Depending on the
        // operation, we might create, open_read, or open_write the file.
        Self { path: path.as_ref() }
    }

    /// Returns the current configured time offset
    fn read_configured_offset(&self) -> Result<Nanos> {
        let mut config_file = fs::File::open(&self.path)
            .with_context(|| format!("Failed to open {}. \
                It is normally created when running the application for the \
                first time via the 'run' command", self.path.display()))?;
        let ts_offset = read_timespec(&mut config_file)?;
        Ok(ts_offset)
    }

    /// Returns the offset to write in the time config file so that if the
    /// application were to call `clock_gettime(CLOCK_MONOTONIC)` immediately, it
    /// would get `app_clock`.
    fn config_time_offset(app_clock: Nanos) -> Nanos {
        let machine_clock = clock_gettime_monotonic();
        machine_clock - app_clock
    }

    /// `read_current_app_clock()` returns the same result as what the application,
    /// virtualized with libvirttime, would get if it were to call
    /// `clock_gettime(CLOCK_MONOTONIC)`.
    pub fn read_current_app_clock(&self) -> Result<Nanos> {
        let config_offset = self.read_configured_offset()?;
        let machine_clock = clock_gettime_monotonic();
        let app_clock = machine_clock - config_offset;
        Ok(app_clock)
    }

    pub fn write_intial(&self) -> Result<()> {
        || -> Result<_> {
            // We arbitrarily start the app clock at 0.
            let app_clock = 0;

            // The time config file must be writable by all users as we are
            // applying a system-wide virtualization configuration.
            let mut config_file = fs::File::create(&self.path)
                .with_context(|| format!("Failed to create {}", self.path.display()))?;

            // We `set_permissions()` after `create()` because our umask may get in the way of
            // the flags we specify in create(). We don't want to change our umask as it is a
            // process-wide setting, and not thread local. So it would be unsafe to restore the
            // previous umask.
            fs::set_permissions(self.path, fs::Permissions::from_mode(0o777))
                .with_context(|| format!("Failed to chmod {}", self.path.display()))?;

            // The config_file has the layout of the `struct virt_time_config`
            write_timespec_at(&config_file, Self::config_time_offset(app_clock), 0)?;

            // Write a 0 at the end of the file to make it the right size
            // without using much space. We add a page to avoid making the hole
            // ends too early.
            config_file.seek(SeekFrom::Current(
                Self::pid_to_fpos(PID_MAX+1) + PAGE_SIZE as i64))?;
            config_file.write_all(&[0])?;

            Ok(())
        }().with_context(|| format!("Failed to write to {}", self.path.display()))
    }

    /// PID to file position in the config file
    fn pid_to_fpos(pid: u32) -> i64 {
        PID_0_FPOS + (pid as i64)*(PROCESS_AREA_SIZE as i64)
    }

    /// file position to PID (rounded down)
    fn fpos_to_pid(fpos: i64) -> u32 {
        ((fpos - PID_0_FPOS)/(PROCESS_AREA_SIZE as i64)) as u32
    }

    /// Rewrite time offsets with the desired `app_clock`
    pub fn adjust_timespecs(&self, app_clock: Nanos) -> Result<()> {
        || -> Result<_> {
            let mut config_file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.path)?;

            let new_time_offset = Self::config_time_offset(app_clock);
            let old_time_offset = read_timespec(&mut config_file)?;
            let old_to_new_time_offset = new_time_offset - old_time_offset;

            // Adjust the global timespec offset
            write_timespec_at(&config_file, new_time_offset, 0)?;

            let mut pid: u32 = 1; // pid=0 does not exist

            // Adjust the threads timespec offsets
            loop {
                // With SEEK_DATA, we'll be skipping pages that have no pids.
                // It seeks to the earlist file position that has data. Typically,
                // we'll be hitting a page boundary.
                let fpos = lseek(config_file.as_raw_fd(), Self::pid_to_fpos(pid),
                                 Whence::SeekData)?;

                // Note: performance could be better as we are doing two
                // syscalls (read+write) per pid. We could improve this to only
                // do two syscalls per page. But that's for another time.

                // Compute the pid corresponding to the file position
                pid = Self::fpos_to_pid(fpos);
                if pid > PID_MAX {
                    break;
                }

                // `fpos_to_pid()` rounds down. If the returned `fpos` does not
                // correspond to the file position of the `pid`, the file
                // position is at a data page boundary. We can skip that pid as
                // we are sure that pid is unused.
                //
                //     |pid ......|pid+1 ......|
                // ... hole  >|< data ...
                //            ^
                //             \ file_offset
                //
                if fpos == Self::pid_to_fpos(pid) {
                    // Read the current timespec, adjust it, and write it back
                    let mut offset = read_timespec(&mut config_file)?;
                    offset += old_to_new_time_offset;
                    write_timespec_at(&mut config_file, offset, fpos)?;
                }

                pid += 1;
            }

            Ok(())
        }().with_context(|| format!(
            "Failed to adjust timespecs in {}", self.path.display()))
    }
}

impl<'a> Default for ConfigPath<'a> {
    fn default() -> Self {
        Self::new(&*VIRT_TIME_CONF_PATH)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Mutex;

    lazy_static! {
        static ref MACHINE_CLOCK: Mutex<Nanos> = Mutex::new(-1);
    }

    pub fn clock_gettime_mock() -> Nanos {
        *MACHINE_CLOCK.lock().unwrap()
    }

    #[test]
    fn test() -> Result<()> {
        let config_path = Path::new("/tmp/ff-test-time-conf");
        let _ = std::fs::remove_file(&config_path);
        let config = ConfigPath::new(&config_path);

        fn read_pid_ts(config_file: &mut fs::File, pid: u32) -> Result<Nanos> {
            config_file.seek(SeekFrom::Start(ConfigPath::pid_to_fpos(pid) as u64))?;
            read_timespec(config_file)
        }

        assert!(config.read_configured_offset().is_err());

        // Clock offset is set to 100, app clock is 0.
        let mut machine_clock = NSEC_IN_SEC + 100;
        let mut app_clock = 0;
        *MACHINE_CLOCK.lock().unwrap() = machine_clock;

        config.write_intial()?;
        let mut config_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config.path)?;

        assert_eq!(config.read_configured_offset()?, machine_clock);
        assert_eq!(config.read_current_app_clock()?, 0);

        // Clock advances by 1000, so app_clock should be 1000
        machine_clock += 1000;
        app_clock += 1000;
        *MACHINE_CLOCK.lock().unwrap() = machine_clock;
        assert_eq!(config.read_current_app_clock()?, app_clock);

        write_timespec_at(&config_file, machine_clock + 100, ConfigPath::pid_to_fpos(1))?;
        write_timespec_at(&config_file, machine_clock + 101, ConfigPath::pid_to_fpos(10000))?;
        write_timespec_at(&config_file, machine_clock + 102, ConfigPath::pid_to_fpos(20000))?;
        write_timespec_at(&config_file, machine_clock + 103, ConfigPath::pid_to_fpos(20001))?;
        write_timespec_at(&config_file, machine_clock + 104, ConfigPath::pid_to_fpos(PID_MAX))?;

        assert_eq!(machine_clock + 100, read_pid_ts(&mut config_file, 1)?);
        assert_eq!(machine_clock + 101, read_pid_ts(&mut config_file, 10000)?);
        assert_eq!(machine_clock + 102, read_pid_ts(&mut config_file, 20000)?);
        assert_eq!(machine_clock + 103, read_pid_ts(&mut config_file, 20001)?);
        assert_eq!(machine_clock + 104, read_pid_ts(&mut config_file, PID_MAX)?);

        // Now let's pretend we checkpoint and move to another machine.
        // app clock is still 1000, but we land on a machine whose clock with a clock in the future
        machine_clock = 10*NSEC_IN_SEC + 100;
        *MACHINE_CLOCK.lock().unwrap() = machine_clock;

        config.adjust_timespecs(app_clock)?; // the app clock we want
        assert_eq!(config.read_current_app_clock()?, app_clock);

        assert_eq!(machine_clock + 100, read_pid_ts(&mut config_file, 1)?);
        assert_eq!(machine_clock + 101, read_pid_ts(&mut config_file, 10000)?);
        assert_eq!(machine_clock + 102, read_pid_ts(&mut config_file, 20000)?);
        assert_eq!(machine_clock + 103, read_pid_ts(&mut config_file, 20001)?);
        assert_eq!(machine_clock + 104, read_pid_ts(&mut config_file, PID_MAX)?);
        assert_eq!(0, read_pid_ts(&mut config_file, 100000)?); // should be not touched

        // What if we go on a machine which time is earlier than ours. This
        // will test overflowing substractions.
        machine_clock = 100;
        *MACHINE_CLOCK.lock().unwrap() = machine_clock;

        config.adjust_timespecs(app_clock)?; // the app clock we want
        assert_eq!(config.read_current_app_clock()?, app_clock);

        assert_eq!(machine_clock + 100, read_pid_ts(&mut config_file, 1)?);
        assert_eq!(machine_clock + 101, read_pid_ts(&mut config_file, 10000)?);
        assert_eq!(machine_clock + 102, read_pid_ts(&mut config_file, 20000)?);
        assert_eq!(machine_clock + 103, read_pid_ts(&mut config_file, 20001)?);
        assert_eq!(machine_clock + 104, read_pid_ts(&mut config_file, PID_MAX)?);
        assert_eq!(0, read_pid_ts(&mut config_file, 100000)?);

        // Time passes
        machine_clock += 500;
        app_clock += 500;
        *MACHINE_CLOCK.lock().unwrap() = machine_clock;

        // App do some calls that use the clock
        write_timespec_at(&config_file, machine_clock + 100, ConfigPath::pid_to_fpos(1))?;
        write_timespec_at(&config_file, machine_clock + 101, ConfigPath::pid_to_fpos(10000))?;
        write_timespec_at(&config_file, machine_clock + 102, ConfigPath::pid_to_fpos(20000))?;
        write_timespec_at(&config_file, machine_clock + 103, ConfigPath::pid_to_fpos(20001))?;
        write_timespec_at(&config_file, machine_clock + 104, ConfigPath::pid_to_fpos(PID_MAX))?;

        // We checkpoint
        assert_eq!(config.read_current_app_clock()?, app_clock);

        // And restore an another machine
        machine_clock = 77;
        *MACHINE_CLOCK.lock().unwrap() = machine_clock;

        config.adjust_timespecs(app_clock)?; // the app clock we want
        assert_eq!(config.read_current_app_clock()?, app_clock);

        assert_eq!(machine_clock + 100, read_pid_ts(&mut config_file, 1)?);
        assert_eq!(machine_clock + 101, read_pid_ts(&mut config_file, 10000)?);
        assert_eq!(machine_clock + 102, read_pid_ts(&mut config_file, 20000)?);
        assert_eq!(machine_clock + 103, read_pid_ts(&mut config_file, 20001)?);
        assert_eq!(machine_clock + 104, read_pid_ts(&mut config_file, PID_MAX)?);
        assert_eq!(0, read_pid_ts(&mut config_file, 100000)?);

        Ok(())
    }
}
