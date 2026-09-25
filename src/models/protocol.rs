use serde::{Deserialize, Serialize};

// Nachrichten, die über den WebSocket laufen (als JSON mit Feld "type").
// Muss mit nexo-server/src/models/protocol.rs übereinstimmen.

#[derive(Debug, Clone, Deserialize)]
pub struct OnlineUser {
    pub public_key: String,
    pub nickname: String,
    // Ändert sich bei jeder neuen Verbindung des Nutzers
    pub connection_id: u64,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Challenge { challenge: String },
    AuthOk { nickname: String },
    AuthError { reason: String },
    OnlineUsers { users: Vec<OnlineUser> },
    // Weitergeleitete Nachricht, "from" ist der Public Key des Absenders
    Received { from: String, payload: String },
    // Der Empfänger war nicht online, die Nachricht wurde verworfen
    NotDelivered { to: String },
    // Wir schicken zu schnell, die Nachricht wurde verworfen
    RateLimited { to: String },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Auth { public_key: String, signature: String },
    // "payload" ist eine PeerMessage als JSON, der Server kann sie nicht lesen
    Send { to: String, payload: String },
}

// Wird vor die Challenge gesetzt und mitsigniert, damit eine Login-Signatur
// nie mit einer anderen Signatur des Clients verwechselt werden kann
pub const AUTH_CONTEXT: &[u8] = b"nexo-auth-v1";
