use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: String,
}

pub fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let data = fs::read_to_string("config.toml")?;
    let config = toml::from_str(&data)?;

    Ok(config)
}