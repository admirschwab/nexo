use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;
use crate::models::encrypted_private_key::EncryptedPrivateKey;

pub fn encrypt_private_key(
    signing_key: &SigningKey,
    password: &str,
) -> Result<EncryptedPrivateKey, Box<dyn std::error::Error>> {
    // Zufälligen Salt erzeugen
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt)?;

    // Aus dem Passwort einen 32-Byte-Schlüssel ableiten
    // (Zeroizing überschreibt ihn beim Verlassen der Funktion mit Nullen)
    let mut encryption_key = Zeroizing::new([0u8; 32]);

    Argon2::default().hash_password_into(
        password.as_bytes(),
        &salt,
        encryption_key.as_mut_slice(),
    )?;

    // XChaCha20-Poly1305 mit dem abgeleiteten Schlüssel erzeugen
    // (die Cipher überschreibt ihre Kopie des Schlüssels beim Freigeben)
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_slice())?;

    // Zufällige Nonce erzeugen
    let mut nonce_bytes = [0u8; 24];
    getrandom::fill(&mut nonce_bytes)?;

    let nonce = XNonce::try_from(nonce_bytes.as_slice())?;

    // Private Key verschlüsseln
    let private_key_bytes = Zeroizing::new(signing_key.to_bytes());

    let ciphertext = cipher.encrypt(
        &nonce,
        private_key_bytes.as_slice(),
    )?;

    Ok(EncryptedPrivateKey {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    })
}
