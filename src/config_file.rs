// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate panic_analysis;
extern crate toml;

use errors::*;
use panic_analysis::{FunctionWhiteListEntry, FunctionWhitelistCrateVersion};

use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct ConfigFileOptions {
    pub function_whitelists: Vec<FunctionWhiteListEntry>,
}

#[derive(Deserialize)]
pub struct FunctionWhiteListTomlEntry {
    function_name: String,
    crate_name: Option<String>,
    crate_version: Option<String>,
    strict: Option<bool>,
}

#[derive(Deserialize)]
pub struct Config {
    whitelisted_functions: Vec<FunctionWhiteListTomlEntry>,
}

impl From<FunctionWhiteListTomlEntry> for FunctionWhiteListEntry {
    fn from(toml: FunctionWhiteListTomlEntry) -> Self {
        let strict = toml.strict.unwrap_or(false);
        FunctionWhiteListEntry {
            function_name: toml.function_name,
            crate_name: toml.crate_name,
            crate_version: toml.crate_version
                .map(|x| {
                    if strict {
                        FunctionWhitelistCrateVersion::Strict(x)
                    } else {
                        FunctionWhitelistCrateVersion::Loose(x)
                    }
                })
                .unwrap_or(FunctionWhitelistCrateVersion::None),
        }
    }
}

pub fn parse_config(path: &str, required: bool) -> Result<ConfigFileOptions> {
    let path = Path::new(path);

    if !path.exists() {
        if required {
            return Err(ErrorKind::ConfigLoad(
                path.to_str().unwrap_or("<unknown>").to_string(),
                Some("File does not exist".to_string()),
            ).into());
        }
        return Ok(ConfigFileOptions::default());
    }

    // Read configuration file
    let mut file = File::open(path).chain_err(|| {
        ErrorKind::ConfigLoad(path.to_str().unwrap_or("<unknown>").to_string(), None)
    })?;

    let mut file_content = Vec::<u8>::new();
    file.read_to_end(&mut file_content).chain_err(|| {
        ErrorKind::ConfigLoad(path.to_str().unwrap_or("<unknown>").to_string(), None)
    })?;

    let config: Config = toml::de::from_slice(&file_content).map_err(|err| {
        ErrorKind::ConfigLoad(
            path.to_str().unwrap_or("<unknown>").to_string(),
            Some(err.to_string()),
        )
    })?;

    Ok(ConfigFileOptions {
        function_whitelists: config
            .whitelisted_functions
            .into_iter()
            .map(FunctionWhiteListEntry::from)
            .collect(),
    })
}
