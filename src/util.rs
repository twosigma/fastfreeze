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
    os::unix::io::{RawFd, AsRawFd, FromRawFd},
    path::{PathBuf, Path},
    env,
    ffi::OsString,
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    io::prelude::*,
    io::SeekFrom,
};
use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag, OFlag},
    poll::{poll, PollFd},
    sched::CloneFlags,
    sys::stat::Mode,
    sys::uio::pwrite,
    unistd::pipe2
};
use crate::{
    consts::*,
    signal::{IsErrorInterrupt, retry_on_interrupt},
};
use serde_json::Value;
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use url::Url;


pub fn gen_random_alphanum_string(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .collect()
}

// This is essentially what stream_len() does in the std lib, but it is
// unstable. We use this in the meantime.
pub fn get_file_size(file: &mut fs::File) -> Result<u64> {
    let old_pos = file.seek(SeekFrom::Current(0))?;
    let len = file.seek(SeekFrom::End(0))?;
    if old_pos != len {
        file.seek(SeekFrom::Start(old_pos))?;
    }
    Ok(len)
}

pub fn get_inheritable_fds() -> Result<Vec<RawFd>> {
    || -> Result<Vec<RawFd>> {
        let mut result = vec![];
        for entry in fs::read_dir("/proc/self/fd")? {
            let fd = entry?.file_name().to_string_lossy().parse()?;
            let fd_flags = fcntl(fd, FcntlArg::F_GETFD)?;
            let fd_flags = FdFlag::from_bits_truncate(fd_flags);
            if !fd_flags.contains(FdFlag::FD_CLOEXEC) {
                result.push(fd);
            }
        }
        Ok(result)
    }().context("Failed to enumerate file descriptors")
}

pub fn readlink_fd(fd: RawFd) -> Result<PathBuf> {
    let path = format!("/proc/self/fd/{}", fd);
    fs::read_link(&path)
        .with_context(|| format!("Failed to readlink {}", &path))
}

pub fn readlinkat(dir: &fs::File, path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    let dir_fd = dir.as_raw_fd();
    nix::fcntl::readlinkat(dir_fd, path)
        .with_context(|| format!("Failed to readlink {}/{}",
            readlink_fd(dir_fd).map(|p| p.display().to_string())
                .unwrap_or_else(|_| "?".to_string()),
            path.display()))
        .map(|p| p.into())
}

pub fn is_term(fd: RawFd) -> bool {
    nix::sys::termios::tcgetattr(fd).is_ok()
}

pub fn pwrite_all(file: &fs::File, buf: &[u8], offset: i64) -> Result<()> {
    let mut buf_off = 0;

    while buf_off < buf.len() {
        let file_offset = offset.checked_add(buf_off as i64).expect("File offset overflown");
        let written = retry_on_interrupt(||
            pwrite(file.as_raw_fd(), &buf[buf_off..], file_offset)
        )?;
        buf_off += written;
    }

    Ok(())
}

pub fn poll_nointr(fds: &mut [PollFd], timeout: libc::c_int) -> nix::Result<libc::c_int>
{
    match poll(fds, timeout) {
        Err(e) if e.is_interrupt() => Ok(0),
        result => result,
    }
}

pub struct Pipe {
    pub read: fs::File,
    pub write: fs::File,
}

impl Pipe {
    pub fn new(flags: OFlag) -> Result<Self> {
        let (fd_r, fd_w) = pipe2(flags).context("Failed to create a pipe")?;
        let read = unsafe { fs::File::from_raw_fd(fd_r) };
        let write = unsafe { fs::File::from_raw_fd(fd_w) };
        Ok(Self { read, write })
    }
}

pub fn create_dir_all(path: impl AsRef<Path>) -> Result<()> {
    fs::create_dir_all(path.as_ref())
        .with_context(|| format!("Failed to create directory {}", path.as_ref().display()))
}

pub fn copy_file(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<u64> {
    fs::copy(from.as_ref(), to.as_ref())
        .with_context(|| format!("Failed to copy file {} to {}",
                                 from.as_ref().display(), to.as_ref().display()))
}

pub fn copy_lib(to: impl AsRef<Path>) -> Result<u64> {
    let to = to.as_ref();
    let libname = to.file_name().expect("file name expected");
    let from = find_lib(libname)?;
    copy_file(from, to)
}

pub fn openat(path: &fs::File, filename: impl AsRef<Path>) -> Result<fs::File> {
    let fd = nix::fcntl::openat(path.as_raw_fd(), filename.as_ref(), OFlag::O_RDONLY, Mode::empty())
        .with_context(|| format!("Failed to open {}", filename.as_ref().display()))?;
    unsafe { Ok(fs::File::from_raw_fd(fd)) }
}

pub fn setns(nsfile: &fs::File, flag: CloneFlags) -> Result<()> {
    let res = unsafe { libc::setns(nsfile.as_raw_fd(), flag.bits()) };
    nix::errno::Errno::result(res)
        .with_context(|| format!("Failed to enter namespace. setns({:?}) failed", flag))
        .map(drop)
}

pub fn find_lib(lib_name: impl AsRef<Path>) -> Result<PathBuf> {
    // We could do a more efficient implementation, but it hurts readability,
    // but we don't do it, because we like readability more.
    let lib_name = lib_name.as_ref();
    let mut search_paths = vec![];
    if let Some(ld_library_paths) = env::var_os("LD_LIBRARY_PATH") {
        search_paths.extend(env::split_paths(&ld_library_paths));
    }
    search_paths.extend(LIB_SEARCH_PATHS.iter().map(PathBuf::from));

    for base_path in search_paths {
        let path = base_path.join(lib_name);
        if path.exists() {
            return Ok(path.canonicalize()?);
        }
    }

    bail!("Failed to find {}. Try adding its directory to LD_LIBRARY_PATH",
          lib_name.display());
}


pub fn atomic_symlink(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    use std::os::unix::fs::symlink;

    // An awkward way to do `format!("{}.tmp", to)` but with OsString
    let mut to_tmp = OsString::from(to.as_ref());
    to_tmp.push(".tmp");

    symlink(from, &to_tmp)?;
    fs::rename(&to_tmp, to)
        .map_err(|e| {
            let _ = fs::remove_file(&to_tmp);
            e
        })?;

    Ok(())
}

pub fn set_tmp_like_permissions(from: impl AsRef<Path>) -> Result<()> {
    fs::set_permissions(from.as_ref(), Permissions::from_mode(0o1777))
        .with_context(|| format!("Failed to chmod 1777 {}", from.as_ref().display()))
}

pub fn get_home_dir() -> Option<PathBuf> {
    // It is said to be deprecated, but it's fine on Linux.
    #[allow(deprecated)]
    std::env::home_dir()
        .and_then(|h| if h.to_string_lossy().is_empty() { None } else { Some(h) })
}

pub trait JsonMerge {
    fn merge(self, b: Value) -> Self;
}

impl JsonMerge for Value {
    fn merge(self, b: Value) -> Self {
        match (self, b) {
            (Value::Object(mut a), Value::Object(b)) => {
                a.extend(b);
                Value::Object(a)
            }
            _ => panic!()
        }
    }
}

pub trait UrlExt {
    fn raw_join(&self, file: &str) -> Url;
}

impl UrlExt for Url {
    fn raw_join(&self, file: &str) -> Url {
        // `Url` provides a join() method, but tries to be too smart
        let mut url = self.clone();
        url.path_segments_mut()
            .expect("URL base error")
            .push(file);
        url
    }
}

#[test]
fn url_join_test() -> Result<()> {
    let url = Url::parse("s3://bucket_name/dir/image_name")?;
    assert_eq!(url.raw_join("file").as_str(), "s3://bucket_name/dir/image_name/file");

    let url = Url::parse("s3://bucket_name/image_name")?;
    assert_eq!(url.raw_join("file").as_str(), "s3://bucket_name/image_name/file");

    let url = Url::parse("s3://bucket_name/")?;
    assert_eq!(url.raw_join("file").as_str(), "s3://bucket_name/file");

    let url = Url::parse("s3://bucket_name")?;
    assert_eq!(url.raw_join("file").as_str(), "s3://bucket_name/file");

    Ok(())
}
