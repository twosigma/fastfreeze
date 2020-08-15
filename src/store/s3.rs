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
use crate::{
    consts::*,
    util::UrlExt,
};

// AWS S3 adapter

lazy_static! {
    static ref S3_CMD: String = std::env::var("S3_CMD")
        .unwrap_or_else(|_| "aws s3".to_string());
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
        // TODO allow users to add an expiration date on images via an env var
        // XXX aws s3 cp eats 500Mb+ of memory. That's terrible when using multiple shards.
        // We'll most likely need to make our own upload tool.

        // This large expected size ensures that there are not too many multiparts pieces
        let expected_size = 10*GB;
        format!("{} cp --expected-size {} - \"{}\"", *S3_CMD, expected_size, self.url)
    }

    fn download_shell_cmd(&self) -> String {
        format!("{} cp \"{}\" -", *S3_CMD, self.url)
    }

    fn has_not_found_error(&self, stderr: &str) -> bool {
        stderr.contains("Not Found")
    }
}
