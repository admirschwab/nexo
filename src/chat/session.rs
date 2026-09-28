use super::crypto::{
    decrypt_text, derive_chat_key, encrypt_text, generate_ephemeral_secret, sign_handshake,
    verify_handshake, HandshakeRole,
};
use crate::models::peer_message::PeerMessage;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use std::{
    error::Error,
    mem,
    time::{Duration, Instant},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

// So lange warten wir auf die Antwort auf einen Handshake, bevor wir ihn neu schicken.
// Die Antwort kann unterwegs verloren gehen, z. B. wenn der Server sie wegen des
// Rate-Limits verwirft. Ohne neuen Versuch würden die Nachrichten ewig warten.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// Nach so vielen Versuchen ohne Antwort geben wir auf
const MAX_HANDSHAKE_ATTEMPTS: u32 = 3;

// Verschlüsselte Sitzung mit einem Gesprächspartner
pub enum Session {
    // Noch kein Schlüsselaustausch
    None,
    // Handshake gesendet, Antwort steht aus. Nachrichten warten solange
    // (und werden beim Verwerfen mit Nullen überschrieben).
    Pending {
        secret: StaticSecret,
        queued: Vec<Zeroizing<String>>,
        sent_at: Instant,
        attempts: u32,
    },
    // Chat-Schlüssel steht (wird beim Verwerfen mit Nullen überschrieben)
    Established {
        key: Zeroizing<[u8; 32]>,
        // Nummer der zuletzt gesendeten Nachricht
        sent: u64,
        // Nummer der zuletzt empfangenen Nachricht. Kleinere oder gleiche Nummern
        // sind erneut eingespielt und werden abgelehnt, Lücken sind verlorene Nachrichten.
        received: u64,
    },
}

pub enum ReceivedText {
    // `lost`: So viele Nachrichten davor sind unterwegs verloren gegangen
    Text { text: String, lost: u64 },
    // Wir hatten keine Sitzung (z. B. nach Neustart). Ein neuer Handshake wurde erzeugt.
    NoSession(Vec<PeerMessage>),
    Invalid,
}

// Ergebnis der regelmäßigen Prüfung eines laufenden Handshakes
pub enum HandshakeTimeout {
    // Nichts zu tun
    Waiting,
    // Keine Antwort: Handshake erneut schicken
    Retry(Vec<PeerMessage>),
    // Auch nach mehreren Versuchen keine Antwort. Enthält die Zahl der
    // wartenden Nachrichten, die damit verloren sind.
    GaveUp(usize),
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
        text: Zeroizing<String>,
    ) -> Result<Vec<PeerMessage>, Box<dyn Error>> {
        match self {
            Session::Established { key, sent, .. } => {
                *sent += 1;
                Ok(vec![encrypt(key, &me.verifying_key(), peer, *sent, &text)?])
            }
            Session::Pending { queued, .. } => {
                queued.push(text);
                Ok(Vec::new())
            }
            Session::None => Ok(vec![self.start_handshake(me, peer, vec![text], 1)?]),
        }
    }

    // Muss regelmäßig aufgerufen werden, damit ein unbeantworteter Handshake
    // wiederholt wird
    pub fn check_timeout(
        &mut self,
        me: &SigningKey,
        peer: &VerifyingKey,
    ) -> Result<HandshakeTimeout, Box<dyn Error>> {
        let Session::Pending { sent_at, attempts, .. } = self else {
            return Ok(HandshakeTimeout::Waiting);
        };

        if sent_at.elapsed() < HANDSHAKE_TIMEOUT {
            return Ok(HandshakeTimeout::Waiting);
        }

        let attempts = *attempts;

        if attempts >= MAX_HANDSHAKE_ATTEMPTS {
            return Ok(HandshakeTimeout::GaveUp(self.reset()));
        }

        let Session::Pending { queued, .. } = mem::replace(self, Session::None) else {
            unreachable!();
        };

        // Neuer Versuch mit frischem Schlüssel. Eine verspätete Antwort auf den
        // vorigen Versuch passt dann nicht mehr und wird ignoriert.
        let handshake = self.start_handshake(me, peer, queued, attempts + 1)?;

        Ok(HandshakeTimeout::Retry(vec![handshake]))
    }

    pub fn receive_handshake(
        &mut self,
        role: HandshakeRole,
        me: &SigningKey,
        peer: &VerifyingKey,
        ephemeral_key: &str,
        signature: &str,
    ) -> Result<Vec<PeerMessage>, Box<dyn Error>> {
        let ephemeral_key: [u8; 32] = hex::decode(ephemeral_key)?
            .try_into()
            .map_err(|_| "Invalid ephemeral key")?;

        let signature = Signature::from_slice(&hex::decode(signature)?)?;
        let their_key = PublicKey::from(ephemeral_key);

        match role {
            HandshakeRole::Init => {
                if !verify_handshake(role, peer, &me.verifying_key(), &ephemeral_key, &signature, None) {
                    return Err("Invalid handshake signature".into());
                }

                match mem::replace(self, Session::None) {
                    // Beide haben gleichzeitig angefangen: Diffie-Hellman ergibt auf
                    // beiden Seiten trotzdem denselben Schlüssel, keine Antwort nötig
                    Session::Pending { secret, queued, .. } => {
                        self.establish(me, peer, &secret, &their_key, queued)
                    }
                    // Der Partner startet eine neue Sitzung: mit eigenem frischem Schlüssel
                    // antworten. Die Antwort wird selbst nie beantwortet, so können sich
                    // zwei Clients nicht endlos gegenseitig neu verschlüsseln.
                    Session::None | Session::Established { .. } => {
                        let secret = generate_ephemeral_secret()?;

                        let key = derive_chat_key(&secret, &their_key)
                            .ok_or("Invalid ephemeral key")?;

                        let reply = handshake_message(
                            HandshakeRole::Reply,
                            me,
                            peer,
                            &secret,
                            Some(&ephemeral_key),
                        );

                        *self = Session::Established {
                            key,
                            sent: 0,
                            received: 0,
                        };

                        Ok(vec![reply])
                    }
                }
            }
            HandshakeRole::Reply => {
                // Nur eine Antwort auf unseren aktuellen Handshake wird angenommen.
                // Doppelte, erneut eingespielte oder verspätete Antworten (auf einen
                // früheren Versuch) werden still ignoriert, die Sitzung bleibt, wie sie ist.
                let Session::Pending { secret, .. } = self else {
                    return Ok(Vec::new());
                };

                let own_key = PublicKey::from(&*secret);

                if !verify_handshake(
                    role,
                    peer,
                    &me.verifying_key(),
                    &ephemeral_key,
                    &signature,
                    Some(own_key.as_bytes()),
                ) {
                    return Ok(Vec::new());
                }

                let Session::Pending { secret, queued, .. } = mem::replace(self, Session::None)
                else {
                    unreachable!();
                };

                self.establish(me, peer, &secret, &their_key, queued)
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
            Session::Established { key, received, .. } => {
                let Some(nonce) = hex::decode(nonce)
                    .ok()
                    .and_then(|bytes| <[u8; 24]>::try_from(bytes).ok())
                else {
                    return ReceivedText::Invalid;
                };

                let Ok(ciphertext) = hex::decode(ciphertext) else {
                    return ReceivedText::Invalid;
                };

                let Some((counter, text)) =
                    decrypt_text(key, peer, &me.verifying_key(), &nonce, &ciphertext)
                else {
                    return ReceivedText::Invalid;
                };

                // Schon gesehen (erneut eingespielt) oder zu alt (vertauschte Reihenfolge)
                if counter <= *received {
                    return ReceivedText::Invalid;
                }

                let lost = counter - *received - 1;
                *received = counter;

                ReceivedText::Text { text, lost }
            }
            // Der Partner hält noch eine alte Sitzung: neu aushandeln
            Session::None => match self.start_handshake(me, peer, Vec::new(), 1) {
                Ok(handshake) => ReceivedText::NoSession(vec![handshake]),
                Err(_) => ReceivedText::Invalid,
            },
            Session::Pending { .. } => ReceivedText::Invalid,
        }
    }

    // Erzeugt einen frischen Schlüssel, wechselt in Pending und gibt den Handshake zurück
    fn start_handshake(
        &mut self,
        me: &SigningKey,
        peer: &VerifyingKey,
        queued: Vec<Zeroizing<String>>,
        attempts: u32,
    ) -> Result<PeerMessage, Box<dyn Error>> {
        let secret = generate_ephemeral_secret()?;
        let handshake = handshake_message(HandshakeRole::Init, me, peer, &secret, None);

        *self = Session::Pending {
            secret,
            queued,
            sent_at: Instant::now(),
            attempts,
        };

        Ok(handshake)
    }

    // Berechnet den Chat-Schlüssel und verschlüsselt die wartenden Nachrichten
    fn establish(
        &mut self,
        me: &SigningKey,
        peer: &VerifyingKey,
        secret: &StaticSecret,
        their_key: &PublicKey,
        queued: Vec<Zeroizing<String>>,
    ) -> Result<Vec<PeerMessage>, Box<dyn Error>> {
        let key = derive_chat_key(secret, their_key).ok_or("Invalid ephemeral key")?;

        let messages = queued
            .iter()
            .zip(1..)
            .map(|(text, counter)| encrypt(&key, &me.verifying_key(), peer, counter, text))
            .collect::<Result<Vec<_>, _>>()?;

        *self = Session::Established {
            key,
            sent: messages.len() as u64,
            received: 0,
        };

        Ok(messages)
    }
}

fn handshake_message(
    role: HandshakeRole,
    me: &SigningKey,
    peer: &VerifyingKey,
    secret: &StaticSecret,
    in_reply_to: Option<&[u8; 32]>,
) -> PeerMessage {
    let ephemeral_key = PublicKey::from(secret);
    let signature = sign_handshake(role, me, &ephemeral_key, peer, in_reply_to);

    let ephemeral_key = hex::encode(ephemeral_key.as_bytes());
    let signature = hex::encode(signature.to_bytes());

    match role {
        HandshakeRole::Init => PeerMessage::HandshakeInit {
            ephemeral_key,
            signature,
        },
        HandshakeRole::Reply => PeerMessage::HandshakeReply {
            ephemeral_key,
            signature,
        },
    }
}

fn encrypt(
    key: &[u8; 32],
    me: &VerifyingKey,
    peer: &VerifyingKey,
    counter: u64,
    text: &str,
) -> Result<PeerMessage, Box<dyn Error>> {
    let (nonce, ciphertext) = encrypt_text(key, me, peer, counter, text)?;

    Ok(PeerMessage::Text {
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}
