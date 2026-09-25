use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey;
use crate::models::encrypted_private_key::EncryptedPrivateKey;

pub fn decrypt_private_key(
    encrypted: &EncryptedPrivateKey,
    password: &str,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    // Aus dem Passwort denselben Schlüssel ableiten
    let mut encryption_key = [0u8; 32];

    Argon2::default().hash_password_into(
        password.as_bytes(),
        &encrypted.salt,
        &mut encryption_key,
    )?;

    // Verschlüsselungsschlüssel erzeugen
    let key = Key::try_from(encryption_key.as_slice())?;
    let cipher = XChaCha20Poly1305::new(&key);

    // Gespeicherte Nonce verwenden
    let nonce = XNonce::try_from(encrypted.nonce.as_slice())?;

    // Private Key entschlüsseln
    let private_key_bytes = cipher.decrypt(
        &nonce,
        encrypted.ciphertext.as_ref(),
    )?;

    // Entschlüsselten Key wieder als SigningKey interpretieren
    let private_key_array: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| "Invalid private key length")?;

    Ok(SigningKey::from_bytes(&private_key_array))
}