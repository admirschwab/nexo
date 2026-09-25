use serde::{Deserialize, Serialize};

// Nachrichten zwischen zwei Clients. Sie stecken im "payload" einer
// ClientMessage::Send und werden vom Server nur weitergereicht.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PeerMessage {
    // Frischer X25519-Schlüssel für diese Sitzung, signiert mit dem Ed25519-Identitätsschlüssel
    Handshake { ephemeral_key: String, signature: String },
    // Verschlüsselte Chat-Nachricht
    Text { nonce: String, ciphertext: String },
}
