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
    ffi::OsString,
    time::Instant,
};
use crate::{
    consts::*,
    process::{Process, Command, ProcessError, ProcessGroupError},
    util::JsonMerge,
};
use serde_json::Value;

lazy_static! {
    static ref METRICS_RECORDER_PATH: Option<OsString> =
        std::env::var_os("FF_METRICS_RECORDER");

    static ref ARGS_JSON: Value =
        serde_json::to_value(std::env::args().collect::<Vec<String>>())
            .expect("Failed to serialize CLI arguments into json");
}

pub fn emit_metrics(event: Value) -> Result<Option<Process>> {
    let metrics_recorder_path = match METRICS_RECORDER_PATH.as_ref() {
        Some(path) => path,
        None => return Ok(None),
    };

    let payload = json!({
        "invocation_id": *INVOCATION_ID,
        "elapsed_time": START_TIME.elapsed().as_secs_f64(),
        "cli_args": *ARGS_JSON,
        "event": event,
    });

    let p = Command::new(&[metrics_recorder_path])
        .arg(&serde_json::to_string(&payload)?)
        .show_cmd_on_spawn(log_enabled!(log::Level::Trace))
        .spawn()
        .context("Failed to spawn the metrics program")?;

    Ok(Some(p))
}

pub fn with_metrics_raw<F,M,R>(action: &str, f: F, metrics_f: M) -> Result<R>
    where F: FnOnce() -> Result<R>,
          M: Fn(&Result<R>) -> Value
{
    if METRICS_RECORDER_PATH.is_none() {
        return f();
    }

    let start_time = Instant::now();
    let result = f();
    let event = json!({
        "action": action,
        "duration": start_time.elapsed().as_secs_f64(),
    }).merge(metrics_f(&result));

    // If the metrics CLI fails, we don't return the error to the caller.
    // Instead, we log the error and move on.
    emit_metrics(event)?.map(|p| p.reap_on_drop());

    result
}

pub fn with_metrics<F,M,R>(action: &str, f: F, metrics_f: M) -> Result<R>
    where F: FnOnce() -> Result<R>,
          M: Fn(&R) -> Value
{
    with_metrics_raw(action, f, |result|
        match result {
            Ok(result) => json!({
                "outcome": "success",
            }).merge(metrics_f(result)),
            Err(e) => json!({
                "outcome": "error",
                "msg": e.to_string(),
            }).merge(metrics_error_json(e)),
        }
    )
}

pub fn metrics_error_json(e: &anyhow::Error) -> Value {
    if let Some(e) = e.downcast_ref::<ProcessError>() {
        json!({"process": e.to_json()})
    }
    else if let Some(e) = e.downcast_ref::<ProcessGroupError>() {
        json!({"process": e.to_json()})
    }
    else {
        json!({})
    }
}
