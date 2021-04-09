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
use url::Url;
use crate::util::UrlExt;

// Google Cloud Storage adapter

lazy_static! {
    static ref GS_CMD: String = std::env::var("GS_CMD")
        .unwrap_or_else(|_| "gcsthin".to_string());
}

pub struct Store {
    url: Url,
}

impl Store {
    pub fn new(url: Url) -> Self {
        Self { url }
    }
}

impl super::Store for Store {
    fn prepare(&self, _write: bool) -> Result<()> {
        Ok(())
    }

    fn file(&self, filename: &str) -> Box<dyn super::File> {
        Box::new(File { url: self.url.raw_join(filename) })
    }
}

pub struct File {
    url: Url,
}

impl super::File for File {
    fn upload_shell_cmd(&self) -> String {
        // TODO Allow lifecycle management options to be configured
        // https://cloud.google.com/storage/docs/managing-lifecycles
        format!("{} cp - \"{}\"", *GS_CMD, self.url)
    }


    fn download_shell_cmd(&self) -> String {
        format!("{} cp \"{}\" -", *GS_CMD, self.url)
    }

    fn has_not_found_error(&self, stderr: &str) -> bool {
        stderr.contains("Not Found") ||
        stderr.contains("No such object")
    }
}
