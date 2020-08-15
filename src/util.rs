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
    os::unix::io::{AsRawFd, FromRawFd},
    path::{PathBuf, Path},
    env,
    ffi::OsString,
    fs,
};
use nix::{
    unistd::pipe2,
    fcntl::OFlag,
    poll::{poll, PollFd},
    sys::uio::pwrite,
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

// `strip_prefix()` is a nighly-only feature.
// We use this polyfill, until it goes into stable.
pub fn strip_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.starts_with(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
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
