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
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub enum Compressor {
    None,
    Lz4,
    Zstd,
}

impl Compressor {
    pub fn compress_cmd(&self) -> Option<&str> {
        match self {
            Compressor::None => None,
            Compressor::Lz4 => Some("lz4 -1 - -"),
            Compressor::Zstd => Some("zstd -1 - -"),
        }
    }

    pub fn decompress_cmd(&self) -> Option<&str> {
        match self {
            Compressor::None => None,
            Compressor::Lz4 => Some("lz4 -d - -"),
            Compressor::Zstd => Some("zstd -d - -"),
        }
    }
}

impl From<CpuBudget> for Compressor {
    fn from(cpu_budget: CpuBudget) -> Self {
        match cpu_budget {
            CpuBudget::Low => Compressor::None,
            CpuBudget::Medium => Compressor::Lz4,
            CpuBudget::High => Compressor::Zstd,
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
