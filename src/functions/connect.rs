use crate::config::Config;
use crate::models::protocol::{ClientMessage, ServerMessage, AUTH_CONTEXT};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use std::error::Error;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, http::StatusCode, Message},
    MaybeTlsStream, WebSocketStream,
};

pub type Connection = WebSocketStream<MaybeTlsStream<TcpStream>>;

// Baut die WebSocket-Verbindung auf und meldet sich per Challenge-Response an.
// Solange die Verbindung offen ist, gilt man beim Server als online.
// Gibt die Verbindung und den Nickname zurück, unter dem der Server uns kennt.
pub async fn connect(
    config: &Config,
    signing_key: &SigningKey,
) -> Result<(Connection, String), Box<dyn Error>> {
    let url = websocket_url(&config.server)?;

    let (mut connection, _) = connect_async(url).await.map_err(|error| match error {
        tungstenite::Error::Http(response)
            if response.status() == StatusCode::TOO_MANY_REQUESTS =>
        {
            "Too many connection attempts. Please wait a moment and try again.".to_string()
        }
        // Der Server (oder ein Reverse Proxy davor) hat geantwortet, aber den
        // WebSocket nicht angenommen, z. B. weil /ws nicht weitergeleitet wird
        tungstenite::Error::Http(response) => format!(
            "The server answered with HTTP {} instead of opening the chat connection. \
             If it runs behind a reverse proxy, check that WebSockets (/ws) are forwarded.",
            response.status()
        ),
        // Die Fehlerursache mit ausgeben (ohne die Server-Adresse, siehe `nexo server`)
        error => format!(
            "Could not reach the Nexo server ({error}). Check the address with `nexo server`."
        ),
    })?;

    let ServerMessage::Challenge { challenge } = next_message(&mut connection).await? else {
        return Err("Unexpected message from server".into());
    };

    let challenge = hex::decode(challenge)?;

    let signed_message = [AUTH_CONTEXT, challenge.as_slice()].concat();
    let signature = signing_key.sign(&signed_message);

    let auth = ClientMessage::Auth {
        public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    };

    connection
        .send(Message::text(serde_json::to_string(&auth)?))
        .await?;

    match next_message(&mut connection).await? {
        ServerMessage::AuthOk { nickname } => Ok((connection, nickname)),
        ServerMessage::AuthError { reason } => Err(reason.into()),
        _ => Err("Unexpected message from server".into()),
    }
}

// http://host -> ws://host/ws, https://host -> wss://host/ws
fn websocket_url(server: &str) -> Result<String, Box<dyn Error>> {
    let server = server.trim_end_matches('/');

    if let Some(rest) = server.strip_prefix("http://") {
        Ok(format!("ws://{rest}/ws"))
    } else if let Some(rest) = server.strip_prefix("https://") {
        Ok(format!("wss://{rest}/ws"))
    } else {
        Err("The server address must start with http:// or https:// (see `nexo server`)".into())
    }
}

async fn next_message(
    connection: &mut Connection,
) -> Result<ServerMessage, Box<dyn Error>> {
    while let Some(message) = connection.next().await {
        match message? {
            Message::Text(text) => return Ok(serde_json::from_str(&text)?),
            Message::Close(_) => break,
            // Ping/Pong usw. ignorieren
            _ => {}
        }
    }

    Err("Connection closed by server".into())
}
