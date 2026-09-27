use crate::config::Config;
use crate::models::identity::Identity;
use crate::models::protocol::REGISTER_CONTEXT;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{Client, StatusCode};
use serde::Serialize;

#[derive(Serialize)]
struct RegisterRequest<'a> {
    public_key: String,
    nickname: &'a str,
    // Beweist dem Server, dass wir den privaten Schlüssel besitzen
    signature: String,
}

pub async fn register_identity(
    config: &Config,
    identity: &Identity,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key = signing_key.verifying_key();

    let signed_message = [
        REGISTER_CONTEXT,
        public_key.as_bytes().as_slice(),
        identity.nickname.as_bytes(),
    ]
        .concat();

    let signature = signing_key.sign(&signed_message);

    let url = format!("{}/register", config.server);

    let response = Client::new()
        .post(&url)
        .json(&RegisterRequest {
            public_key: hex::encode(public_key.to_bytes()),
            nickname: &identity.nickname,
            signature: hex::encode(signature.to_bytes()),
        })
        .send()
        .await
        .map_err(|_| format!("Could not reach the Nexo server at {}", config.server))?;

    match response.status() {
        status if status.is_success() => Ok(()),
        StatusCode::CONFLICT => Err(
            format!("The nickname '{}' is already taken", identity.nickname).into(),
        ),
        StatusCode::BAD_REQUEST => Err("The server rejected the nickname or public key".into()),
        StatusCode::TOO_MANY_REQUESTS => {
            Err("Too many registrations from your network. Please try again later.".into())
        }
        status => Err(format!("Server rejected registration: {status}").into()),
    }
}
