use crate::config::Config;
use crate::models::protocol::UNREGISTER_CONTEXT;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{Client, StatusCode};
use serde::Serialize;

#[derive(Serialize)]
struct UnregisterRequest {
    public_key: String,
    // Beweist dem Server, dass das Konto uns gehört
    signature: String,
}

// Löscht das Konto (Public Key + Nickname) auf dem Server
pub async fn unregister_identity(
    config: &Config,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key = signing_key.verifying_key();

    let signed_message = [UNREGISTER_CONTEXT, public_key.as_bytes().as_slice()].concat();
    let signature = signing_key.sign(&signed_message);

    let url = format!("{}/unregister", config.server);

    let response = Client::new()
        .post(&url)
        .json(&UnregisterRequest {
            public_key: hex::encode(public_key.to_bytes()),
            signature: hex::encode(signature.to_bytes()),
        })
        .send()
        .await
        .map_err(|_| format!("Could not reach the Nexo server at {}", config.server))?;

    match response.status() {
        status if status.is_success() => Ok(()),
        StatusCode::NOT_FOUND => Err(
            "This identity is not registered on the server. Nothing was deleted. \
             Check the server address in config.toml."
                .into(),
        ),
        StatusCode::TOO_MANY_REQUESTS => {
            Err("Too many requests from your network. Please try again later.".into())
        }
        status => Err(format!("Server rejected the request: {status}").into()),
    }
}
