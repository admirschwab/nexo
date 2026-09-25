use super::crypto::{
    decrypt_text, derive_chat_key, encrypt_text, generate_ephemeral_secret, sign_handshake,
    verify_handshake,
};
use crate::models::peer_message::PeerMessage;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use std::{collections::HashSet, error::Error, mem};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

// Verschlüsselte Sitzung mit einem Gesprächspartner
pub enum Session {
    // Noch kein Schlüsselaustausch
    None,
    // Handshake gesendet, Antwort steht aus. Nachrichten warten solange.
    Pending {
        secret: StaticSecret,
        queued: Vec<String>,
    },
    // Chat-Schlüssel steht (wird beim Verwerfen mit Nullen überschrieben)
    Established {
        key: Zeroizing<[u8; 32]>,
        // Schutz gegen erneut eingespielte Nachrichten
        seen_nonces: HashSet<[u8; 24]>,
    },
}

pub enum ReceivedText {
    Text(String),
    // Wir hatten keine Sitzung (z. B. nach Neustart). Ein neuer Handshake wurde erzeugt.
    NoSession(Vec<PeerMessage>),
    Invalid,
}

impl Session {
    pub fn is_established(&self) -> bool {
        matches!(self, Session::Established { .. })
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Session::Pending { .. })
    }

    // Verwirft alle Schlüssel. Gibt zurück, wie viele wartende Nachrichten verloren gehen.
    pub fn reset(&mut self) -> usize {
        match mem::replace(self, Session::None) {
            Session::Pending { queued, .. } => queued.len(),
            _ => 0,
        }
    }

    // Gibt die Nachrichten zurück, die an den Partner geschickt werden müssen
    pub fn send_text(
        &mut self,
        me: &SigningKey,
        peer: &VerifyingKey,
        text: String,
    ) -> Result<Vec<PeerMessage>, Box<dyn Error>> {
        match self {
            Session::Established { key, .. } => {
                Ok(vec![encrypt(key, &me.verifying_key(), peer, &text)?])
            }
            Session::Pending { queued, .. } => {
                queued.push(text);
                Ok(Vec::new())
            }
            Session::None => {
                let secret = generate_ephemeral_secret()?;
                let handshake = handshake_message(me, peer, &secret);

                *self = Session::Pending {
                    secret,
                    queued: vec![text],
                };

                Ok(vec![handshake])
            }
        }
    }

    pub fn receive_handshake(
        &mut self,
        me: &SigningKey,
        peer: &VerifyingKey,
        ephemeral_key: &str,
        signature: &str,
    ) -> Result<Vec<PeerMessage>, Box<dyn Error>> {
        let ephemeral_key: [u8; 32] = hex::decode(ephemeral_key)?
            .try_into()
            .map_err(|_| "Invalid ephemeral key")?;

        let signature = Signature::from_slice(&hex::decode(signature)?)?;

        if !verify_handshake(peer, &me.verifying_key(), &ephemeral_key, &signature) {
            return Err("Invalid handshake signature".into());
        }

        let their_key = PublicKey::from(ephemeral_key);

        match mem::replace(self, Session::None) {
            // Antwort auf unseren Handshake (oder beide haben gleichzeitig angefangen,
            // dann ergibt Diffie-Hellman auf beiden Seiten trotzdem denselben Schlüssel)
            Session::Pending { secret, queued } => {
                let key = derive_chat_key(&secret, &their_key)
                    .ok_or("Invalid ephemeral key")?;

                let messages = queued
                    .iter()
                    .map(|text| encrypt(&key, &me.verifying_key(), peer, text))
                    .collect::<Result<Vec<_>, _>>()?;

                *self = Session::Established {
                    key,
                    seen_nonces: HashSet::new(),
                };

                Ok(messages)
            }
            // Der Partner startet eine neue Sitzung: mit eigenem frischem Schlüssel antworten
            Session::None | Session::Established { .. } => {
                let secret = generate_ephemeral_secret()?;

                let key = derive_chat_key(&secret, &their_key)
                    .ok_or("Invalid ephemeral key")?;

                let reply = handshake_message(me, peer, &secret);

                *self = Session::Established {
                    key,
                    seen_nonces: HashSet::new(),
                };

                Ok(vec![reply])
            }
        }
    }

    pub fn receive_text(
        &mut self,
        me: &SigningKey,
        peer: &VerifyingKey,
        nonce: &str,
        ciphertext: &str,
    ) -> ReceivedText {
        match self {
            Session::Established { key, seen_nonces } => {
                let Some(nonce) = hex::decode(nonce)
                    .ok()
                    .and_then(|bytes| <[u8; 24]>::try_from(bytes).ok())
                else {
                    return ReceivedText::Invalid;
                };

                let Ok(ciphertext) = hex::decode(ciphertext) else {
                    return ReceivedText::Invalid;
                };

                if seen_nonces.contains(&nonce) {
                    return ReceivedText::Invalid;
                }

                match decrypt_text(key, peer, &me.verifying_key(), &nonce, &ciphertext) {
                    Some(text) => {
                        seen_nonces.insert(nonce);
                        ReceivedText::Text(text)
                    }
                    None => ReceivedText::Invalid,
                }
            }
            // Der Partner hält noch eine alte Sitzung: neu aushandeln
            Session::None => match generate_ephemeral_secret() {
                Ok(secret) => {
                    let handshake = handshake_message(me, peer, &secret);

                    *self = Session::Pending {
                        secret,
                        queued: Vec::new(),
                    };

                    ReceivedText::NoSession(vec![handshake])
                }
                Err(_) => ReceivedText::Invalid,
            },
            Session::Pending { .. } => ReceivedText::Invalid,
        }
    }
}

fn handshake_message(
    me: &SigningKey,
    peer: &VerifyingKey,
    secret: &StaticSecret,
) -> PeerMessage {
    let ephemeral_key = PublicKey::from(secret);
    let signature = sign_handshake(me, &ephemeral_key, peer);

    PeerMessage::Handshake {
        ephemeral_key: hex::encode(ephemeral_key.as_bytes()),
        signature: hex::encode(signature.to_bytes()),
    }
}

fn encrypt(
    key: &[u8; 32],
    me: &VerifyingKey,
    peer: &VerifyingKey,
    text: &str,
) -> Result<PeerMessage, Box<dyn Error>> {
    let (nonce, ciphertext) = encrypt_text(key, me, peer, text)?;

    Ok(PeerMessage::Text {
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}
