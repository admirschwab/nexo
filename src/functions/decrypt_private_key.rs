use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;
use crate::models::encrypted_private_key::EncryptedPrivateKey;

pub fn decrypt_private_key(
    encrypted: &EncryptedPrivateKey,
    password: &str,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    // Aus dem Passwort denselben Schlüssel ableiten
    // (Zeroizing überschreibt ihn beim Verlassen der Funktion mit Nullen)
    let mut encryption_key = Zeroizing::new([0u8; 32]);

    Argon2::default().hash_password_into(
        password.as_bytes(),
        &encrypted.salt,
        encryption_key.as_mut_slice(),
    )?;

    // Cipher erzeugen (überschreibt ihre Kopie des Schlüssels beim Freigeben)
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_slice())?;

    // Gespeicherte Nonce verwenden
    let nonce = XNonce::try_from(encrypted.nonce.as_slice())?;

    // Private Key entschlüsseln
    let private_key_bytes = Zeroizing::new(cipher.decrypt(
        &nonce,
        encrypted.ciphertext.as_ref(),
    )?);

    // Entschlüsselten Key wieder als SigningKey interpretieren
    let private_key_array: Zeroizing<[u8; 32]> = Zeroizing::new(
        private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid private key length")?,
    );

    // SigningKey überschreibt sich selbst beim Freigeben
    Ok(SigningKey::from_bytes(&private_key_array))
}
