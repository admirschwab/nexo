use crate::config::Config;
use crate::models::identity::Identity;
use ed25519_dalek::SigningKey;
use reqwest::blocking::Client;
use serde_json::json;

pub fn register_identity(
    config: &Config,
    identity: &Identity,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key = signing_key.verifying_key();

    let body = json!({
        "public_key": hex::encode(public_key.to_bytes()),
        "nickname": identity.nickname,
    });

    let client = Client::new();

    let url = format!("{}/register", config.server);

    let response = client
        .post(&url)
        .json(&body)
        .send()?;

    if !response.status().is_success() {
        return Err(
            format!("Server rejected registration: {}", response.status()).into()
        );
    }

    Ok(())
}