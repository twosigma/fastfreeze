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

use serde::{Serialize, Deserialize};
use std::{
    str::FromStr,
    fmt,
};

#[derive(Debug, Serialize, Deserialize)]
pub enum Compression {
    Lz4,
    Zstd,
}

impl Compression {
    pub fn compress_cmd(&self) -> &str {
        match self {
            Compression::Lz4 => "lz4 -1 - -",
            Compression::Zstd => "zstd -1 - -",
        }
    }

    pub fn decompress_cmd(&self) -> &str {
        match self {
            Compression::Lz4 => "lz4 -d - -",
            Compression::Zstd => "zstd -d - -",
        }
    }
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Compression::Lz4 => write!(f, "lz4"),
            Compression::Zstd => write!(f, "zstd"),
        }
    }
}


impl From<CpuBudget> for Option<Compression> {
    fn from(cpu_budget: CpuBudget) -> Self {
        match cpu_budget {
            CpuBudget::Low => None,
            CpuBudget::Medium => Some(Compression::Lz4),
            CpuBudget::High => Some(Compression::Zstd),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
pub enum CpuBudget {
    Low,
    Medium,
    High,
}

impl FromStr for CpuBudget {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "low"    => CpuBudget::Low,
            "medium" => CpuBudget::Medium,
            "high"   => CpuBudget::High,
            _ => bail!("Possible values are [low, medium, high], not `{}`", s)
        })
    }
}
