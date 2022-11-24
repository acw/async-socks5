use super::ConfigError;
use etcetera::base_strategy::{choose_base_strategy, BaseStrategy};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::metadata::LevelFilter;

#[derive(serde_derive::Deserialize, Default)]
pub struct ConfigFile {
    #[serde(deserialize_with = "parse_log_level")]
    pub log_level: Option<LevelFilter>,
    pub start_servers: Option<String>,
    #[serde(flatten)]
    pub servers: HashMap<String, ServerDefinition>,
}

#[derive(serde_derive::Deserialize)]
pub struct ServerDefinition {
    pub interface: Option<String>,
    #[serde(deserialize_with = "parse_log_level")]
    pub log_level: Option<LevelFilter>,
    pub address: Option<String>,
    pub port: Option<u16>,
}

fn parse_log_level<'de, D>(deserializer: D) -> Result<Option<LevelFilter>, D::Error>
where
    D: Deserializer<'de>,
{
    let possible_string: Option<&str> = Deserialize::deserialize(deserializer)?;

    if let Some(s) = possible_string {
        Ok(Some(s.parse().map_err(|e| {
            serde::de::Error::custom(format!("Couldn't parse log level '{}': {}", s, e))
        })?))
    } else {
        Ok(None)
    }
}

impl ConfigFile {
    pub fn read(mut config_file_path: Option<PathBuf>) -> Result<ConfigFile, ConfigError> {
        if config_file_path.is_none() {
            let base_dirs = choose_base_strategy()
                .map_err(|e| ConfigError::HostDirectoryError(e.to_string()))?;
            let mut proposed_path = base_dirs.config_dir();
            proposed_path.push("socks5");
            if let Ok(attributes) = fs::metadata(proposed_path.clone()) {
                if attributes.is_file() {
                    config_file_path = Some(proposed_path);
                }
            }
        }

        match config_file_path {
            None => Ok(ConfigFile::default()),
            Some(path) => {
                let content = fs::read(path)?;
                Ok(toml::from_slice(&content)?)
            }
        }
    }
}
