use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

// Gemerkte Schlüssel ("Trust on first use")
//
// Beim ersten Chat mit jemandem merken wir uns, welcher Public Key zu seinem
// Nickname gehört. Schiebt uns der Server später unter demselben Nickname einen
// anderen Schlüssel unter (um mitzulesen), fällt das auf.
//
// Die Datei ist verschlüsselt, mit einem Schlüssel, der aus dem privaten
// Identitätsschlüssel abgeleitet wird. Ohne Passwort sieht also niemand,
// mit wem man geschrieben hat.

const FILE_MAGIC: &[u8] = b"NEXP1";
const FILE_KEY_INFO: &[u8] = b"nexo-known-peers-key-v1";

#[derive(Clone, Serialize, Deserialize)]
struct KnownPeer {
    nickname: String,
    public_key: String,
}

// Wie ein Gesprächspartner zu den gemerkten Schlüsseln passt
#[derive(Clone, PartialEq)]
pub enum PeerTrust {
    // Noch nie mit ihm geschrieben
    New,
    // Nickname und Schlüssel passen zu dem, was wir uns gemerkt haben
    Known,
    // Unter diesem Nickname kannten wir einen anderen Schlüssel: möglicher Angriff
    KeyChanged,
    // Diesen Schlüssel kannten wir unter einem anderen Nickname
    NicknameChanged { previous: String },
}

impl PeerTrust {
    pub fn is_warning(&self) -> bool {
        matches!(self, PeerTrust::KeyChanged | PeerTrust::NicknameChanged { .. })
    }
}

pub struct KnownPeers {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    peers: Vec<KnownPeer>,
}

impl KnownPeers {
    // Lädt die Datei. Gibt es sie noch nicht, beginnen wir mit einer leeren Liste.
    pub fn load(path: &Path, signing_key: &SigningKey) -> Result<Self, Box<dyn Error>> {
        let key = derive_file_key(signing_key)?;

        let peers = if path.exists() {
            decrypt_peers(&fs::read(path)?, &key).ok_or_else(|| {
                format!(
                    "{} could not be decrypted. It is corrupted or belongs to another identity.",
                    path.display()
                )
            })?
        } else {
            Vec::new()
        };

        Ok(Self {
            path: path.to_path_buf(),
            key,
            peers,
        })
    }

    pub fn check(&self, nickname: &str, public_key: &str) -> PeerTrust {
        let by_nickname = self
            .peers
            .iter()
            .find(|peer| peer.nickname.eq_ignore_ascii_case(nickname));

        if let Some(peer) = by_nickname {
            return if peer.public_key == public_key {
                PeerTrust::Known
            } else {
                PeerTrust::KeyChanged
            };
        }

        match self.peers.iter().find(|peer| peer.public_key == public_key) {
            Some(peer) => PeerTrust::NicknameChanged {
                previous: peer.nickname.clone(),
            },
            None => PeerTrust::New,
        }
    }

    // Merkt sich Nickname und Schlüssel. Ältere Einträge mit demselben Nickname
    // oder demselben Schlüssel werden dabei ersetzt.
    pub fn remember(&mut self, nickname: &str, public_key: &str) -> Result<(), Box<dyn Error>> {
        self.peers.retain(|peer| {
            !peer.nickname.eq_ignore_ascii_case(nickname) && peer.public_key != public_key
        });

        self.peers.push(KnownPeer {
            nickname: nickname.to_string(),
            public_key: public_key.to_string(),
        });

        self.save()
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let data = encrypt_peers(&self.peers, &self.key)?;

        // Erst in eine Zwischendatei schreiben, dann ersetzen.
        // So bleibt bei einem Absturz immer eine vollständige Datei übrig.
        let mut temp_path = self.path.clone().into_os_string();
        temp_path.push(".tmp");
        let temp_path = PathBuf::from(temp_path);

        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);

        // Unter Linux/macOS darf nur der Besitzer die Datei lesen
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&temp_path)?;
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&temp_path, &self.path)?;

        Ok(())
    }
}

fn derive_file_key(signing_key: &SigningKey) -> Result<Zeroizing<[u8; 32]>, Box<dyn Error>> {
    let secret = Zeroizing::new(signing_key.to_bytes());
    let mut key = Zeroizing::new([0u8; 32]);

    Hkdf::<Sha256>::new(None, secret.as_slice())
        .expand(FILE_KEY_INFO, key.as_mut_slice())
        .map_err(|_| "Could not derive key for known peers")?;

    Ok(key)
}

// Format: FILE_MAGIC + Nonce (24 Bytes) + verschlüsseltes JSON
fn encrypt_peers(peers: &[KnownPeer], key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
    let plaintext = Zeroizing::new(serde_json::to_vec(peers)?);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())?;

    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce)?;

    let ciphertext = cipher.encrypt(
        &XNonce::try_from(nonce.as_slice())?,
        Payload {
            msg: &plaintext,
            aad: FILE_MAGIC,
        },
    )?;

    Ok([FILE_MAGIC, nonce.as_slice(), ciphertext.as_slice()].concat())
}

fn decrypt_peers(data: &[u8], key: &[u8; 32]) -> Option<Vec<KnownPeer>> {
    let rest = data.strip_prefix(FILE_MAGIC)?;

    if rest.len() < 24 {
        return None;
    }

    let (nonce, ciphertext) = rest.split_at(24);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).ok()?;

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::try_from(nonce).ok()?,
                Payload {
                    msg: ciphertext,
                    aad: FILE_MAGIC,
                },
            )
            .ok()?,
    );

    serde_json::from_slice(&plaintext).ok()
}
