use crate::config::Config;
use ed25519_dalek::Signer;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Serialize)]
struct ChallengeRequest {
    public_key: String,
}

#[derive(Serialize)]
struct VerifyRequest {
    public_key: String,
    signature: String,
}

#[derive(Deserialize)]
struct VerifyResponse {
    success: bool,
    nickname: String,
}

// Beweist dem Server per Signatur, dass wir den Private Key besitzen.
// Gibt den Nickname zurück, unter dem der Server uns kennt.
pub async fn authenticate(
    config: &Config,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<String, Box<dyn Error>> {
    let client = Client::new();

    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let unreachable =
        |_| format!("Could not reach the Nexo server at {}", config.server);

    let response = client
        .post(format!("{}/auth/challenge", config.server))
        .json(&ChallengeRequest {
            public_key: public_key_hex.clone(),
        })
        .send()
        .await
        .map_err(unreachable)?;

    if response.status() == StatusCode::NOT_FOUND {
        return Err("This identity is not registered on the server".into());
    }

    let challenge_response = response
        .error_for_status()?
        .json::<ChallengeResponse>()
        .await?;

    let challenge = hex::decode(challenge_response.challenge)?;

    let signature = signing_key.sign(&challenge);

    let response = client
        .post(format!("{}/auth/verify", config.server))
        .json(&VerifyRequest {
            public_key: public_key_hex,
            signature: hex::encode(signature.to_bytes()),
        })
        .send()
        .await
        .map_err(unreachable)?;

    if response.status() == StatusCode::UNAUTHORIZED {
        return Err("Authentication failed".into());
    }

    let verify_response = response
        .error_for_status()?
        .json::<VerifyResponse>()
        .await?;

    if !verify_response.success {
        return Err("Authentication failed".into());
    }

    Ok(verify_response.nickname)
}
