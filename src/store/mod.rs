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
use std::io::Write;
use url::Url;
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
    fn write(&self, data: &[u8]) -> Result<()> {
        let mut p = Command::new_shell(self.upload_shell_cmd())
            .stdin(Stdio::piped())
            .spawn()?;

        p.stdin().write_all(data)
            .context("Failed to write() into the upload process")?;
        p.wait_for_success()
    }

    /// Reads a file. Returns None if it doesn't exist.
    fn try_read(&self) -> Result<Option<Vec<u8>>> {
        let p = Command::new_shell(self.download_shell_cmd())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let output = p.wait_with_output()?;
        if output.status.success() {
            Ok(Some(output.stdout))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if self.has_not_found_error(&stderr) {
                Ok(None)
            } else  {
                eprint!("{}", stderr);
                Err(output.ensure_success().unwrap_err())
            }
        }
    }
}
impl FileExt for dyn File {}

/// Returns a store corresponding to the provided `url`.
pub fn from_url(url: &str) -> Result<Box<dyn Store>> {
    let url = Url::parse(url)?;

    Ok(match url.scheme() {
        "file" => Box::new(local::Store::new(url)),
        "s3"   => Box::new(s3::Store::new(url)),
        "gs"   => Box::new(gs::Store::new(url)),
        _ => bail!("Unknown image scheme {}", url),
    })
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_url() {
        assert!(from_url("file:/tmp/img").is_ok());
        assert!(from_url("file:tmp/img").is_ok());
    }

    fn test_store_read_write(store: &Box<dyn Store>) -> Result<()> {
        store.prepare(true)?;
        store.file("f1.txt").write("hello".as_bytes())?;
        assert_eq!(store.file("f1.txt").try_read()?, Some("hello".as_bytes().to_vec()));
        assert_eq!(store.file("none.txt").try_read()?, None);
        Ok(())
    }

    #[test]
    fn test_read_write() -> Result<()> {
        test_store_read_write(&from_url("file:/tmp/ff-test-files")?)?;
        Ok(())
    }
}
