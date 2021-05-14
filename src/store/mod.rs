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

mod local;
mod s3;
mod gs;

use anyhow::{Result, Context};
use std::{
    borrow::Cow,
    fmt,
    io::Write,
};
use url::{Url, ParseError};
use crate::process::{Stdio, Command};

// `Store` and `File` describe the API needed to store and retrieve images

pub trait Store {
    /// prepare() is called before accessing the storage. It is called:
    /// * with write=true, during the FastFreeze run command
    /// * with write=false, during the FastFreeze extract command
    /// It is not called during the checkpoint command to speed things up.
    fn prepare(&self, write: bool) -> Result<()>;

    /// Returns a File object that represents a file of name `filename`.
    /// Example of file name are "manifest.json" and "XXXX-4.ffs".
    fn file(&self, filename: &str) -> Box<dyn File>;
}

pub trait File {
    /// Returns a shell command to upload file
    fn upload_shell_cmd(&self) -> String;

    /// Returns a shell command to download file
    fn download_shell_cmd(&self) -> String;

    // Returns whether stderr contains a "not found error" when the download
    // shell command failed.
    fn has_not_found_error(&self, stderr: &str) -> bool;
}

// write()/try_read() are helpers that use the `File` download/upload shell
// commands to download and upload content.
pub trait FileExt: File {
    /// Write content to the file, truncating it if necessary.
    fn write(&self, log_prefix: &'static str, data: &[u8]) -> Result<()> {
        let mut p = Command::new_shell(&self.upload_shell_cmd())
            .stdin(Stdio::piped())
            .enable_stderr_logging(log_prefix)
            .spawn()?;

        // We are simultaneously writing to stdin and reading stderr.
        // While we are writing to stdin, the upload shell command might be
        // blocking on us to drain stderr, leading to a deadlock.
        // We use a thread to avoid complications. It's a bit overkill, but works.

        // With a scoped thread, we wouldn't need the data copy, but it's okay
        // we just use it to copy a small json file (the manifest).
        let data = Vec::from(data);
        let mut stdin = p.take_stdin().expect("stdin isn't connected");
        let stdin_write_thread = std::thread::spawn(move || stdin.write_all(&data));

        p.wait_for_success()?;

        stdin_write_thread.join().expect("thread panic")
            .with_context(|| format!("{}> write to stdin failed", log_prefix))
    }

    /// Reads a file. Returns None if it doesn't exist.
    fn try_read<S>(&self, log_prefix: S) -> Result<Option<Vec<u8>>>
        where S: Into<Cow<'static, str>>
    {
        let log_prefix = log_prefix.into();
        let p = Command::new_shell(&self.download_shell_cmd())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let output = p.wait_with_output()?;
        if output.status.success() {
            Ok(Some(output.stdout))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if self.has_not_found_error(&stderr) {
                trace!("{}> File does not exist. stderr is: {}", log_prefix, stderr);
                Ok(None)
            } else {
                Err(output.ensure_success_with_stderr_log(log_prefix).unwrap_err())
            }
        }
    }
}
impl FileExt for dyn File {}

pub struct ImageUrl(Url);

impl ImageUrl {
    /// If url does not start with "scheme:", it is assumed to be a file path.
    pub fn parse(url_str: &str) -> Result<Self> {
        match Url::parse(url_str) {
            Err(ParseError::RelativeUrlWithoutBase) => {
                ensure!(url_str.starts_with('/'),
                        "Please use an absolute path for the image path");
                Self::parse(&format!("file:{}", url_str))
            },
            Err(e) => bail!(e),
            Ok(url) => {
                {
                    let path = url.path();
                    ensure!(url.path_segments().is_some(), "Image URL path is empty");
                    ensure!(path.chars().last() != Some('/'), "Image URL path should not end with a trailing /");
                }

                Ok(Self(match url.scheme() {
                    "file" => {
                        // The url parser prefix the relative paths with /, and we
                        // have no way to know once parsed. Which is why we do error
                        // detection here, and not in local::Store.
                        ensure!(url_str.starts_with("file:/"),
                            "Please use an absolute path for the image path");
                        url
                    },
                    "s3" | "gs"  => url,
                    _ => bail!("Unknown image scheme {}", url),
                }))
            }
        }
    }

    pub fn image_name(&self) -> &str {
        // The unwraps are okay, we already validated that we have some in parse_image_url().
        self.0.path_segments().unwrap().last().unwrap()
    }

    pub fn store(&self) -> Box<dyn Store> {
        match self.0.scheme() {
            "file" => Box::new(local::Store::new(self.0.path())),
            "s3"   => Box::new(s3::Store::new(self.0.clone())),
            "gs"   => Box::new(gs::Store::new(self.0.clone())),
            // panic!() is okay, validation is already done in parse().
            _      => panic!("Unknown image scheme"),
        }
    }
}

impl fmt::Display for ImageUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_url() {
        assert!(ImageUrl::parse("file:/tmp/img").is_ok());
        assert!(ImageUrl::parse("file:tmp/img").is_err());
    }

    fn test_store_read_write(store: &Box<dyn Store>) -> Result<()> {
        store.prepare(true)?;
        store.file("f1.txt").write("test", "hello".as_bytes())?;
        assert_eq!(store.file("f1.txt").try_read("read test")?, Some("hello".as_bytes().to_vec()));
        assert_eq!(store.file("none.txt").try_read("read test")?, None);
        Ok(())
    }

    #[test]
    fn test_read_write() -> Result<()> {
        test_store_read_write(&ImageUrl::parse("file:/tmp/ff-test-files")?.store())?;
        Ok(())
    }
}
