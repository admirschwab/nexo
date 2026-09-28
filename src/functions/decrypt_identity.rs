use crate::functions::derive_file_key::derive_file_key;
use crate::models::{
    encrypted_identity::{EncryptedIdentity, IdentityFormat},
    identity::Identity,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

pub fn decrypt_identity(
    encrypted: &EncryptedIdentity,
    password: &str,
) -> Result<Identity, Box<dyn std::error::Error>> {
    // Aus dem Passwort denselben Schlüssel ableiten
    let encryption_key = derive_file_key(password, &encrypted.salt, &encrypted.kdf)?;

    // Die Cipher überschreibt ihre Kopie des Schlüssels beim Freigeben
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_slice())?;

    // Format 1 hatte keinen geschützten Kopf
    let aad = match encrypted.format {
        IdentityFormat::V1 { .. } => Vec::new(),
        IdentityFormat::V2 => {
            EncryptedIdentity::header_v2(&encrypted.kdf, &encrypted.salt, &encrypted.nonce)
        }
    };

    let plaintext = Zeroizing::new(cipher.decrypt(
        &XNonce::try_from(encrypted.nonce.as_slice())?,
        Payload {
            msg: &encrypted.ciphertext,
            aad: &aad,
        },
    )?);

    if plaintext.len() < 32 {
        return Err("Invalid private key length".into());
    }

    let (key_bytes, nickname_bytes) = plaintext.split_at(32);

    let private_key: Zeroizing<[u8; 32]> = Zeroizing::new(
        key_bytes
            .try_into()
            .map_err(|_| "Invalid private key length")?,
    );

    let nickname = match &encrypted.format {
        IdentityFormat::V1 { nickname } => {
            if !nickname_bytes.is_empty() {
                return Err("Invalid private key length".into());
            }

            nickname.clone()
        }
        IdentityFormat::V2 => String::from_utf8(nickname_bytes.to_vec())?,
    };

    Ok(Identity {
        nickname,
        signing_key: SigningKey::from_bytes(&private_key),
    })
}
