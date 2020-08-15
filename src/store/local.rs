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

use anyhow::Result;
use std::path::PathBuf;
use url::Url;
use crate::util::create_dir_all;

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(url: Url) -> Self {
        Self { path: PathBuf::from(url.path()) }
    }
}

impl super::Store for Store {
    fn prepare(&self, write: bool) -> Result<()> {
        if write {
            create_dir_all(&self.path)?;
        }

        Ok(())
    }

    fn file(&self, filename: &str) -> Box<dyn super::File> {
        let file_path = if filename == "/dev/null" {
            PathBuf::from("/dev/null")
        } else {
            self.path.join(filename)
        };

        Box::new(File { path: file_path })
    }
}

pub struct File {
    path: PathBuf,
}

impl super::File for File {
    fn upload_shell_cmd(&self) -> String {
        // We can unwrap() because the path is valid UTF8, as path comes from a String
        format!("pv -q > \"{}\"", self.path.to_str().unwrap())
    }

    fn download_shell_cmd(&self) -> String {
        format!("pv -q \"{}\"", self.path.to_str().unwrap())
    }

    fn has_not_found_error(&self, stderr: &str) -> bool {
        stderr.contains("No such file or directory")
    }
}
