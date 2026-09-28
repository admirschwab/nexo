use crate::functions::derive_file_key::derive_file_key;
use crate::models::{
    encrypted_identity::{EncryptedIdentity, IdentityFormat, KdfParams},
    identity::Identity,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

// Verschlüsselt privaten Schlüssel und Nickname mit dem Passwort (immer Format 2)
pub fn encrypt_identity(
    identity: &Identity,
    password: &str,
) -> Result<EncryptedIdentity, Box<dyn std::error::Error>> {
    let kdf = KdfParams::CURRENT;

    // Zufälliger Salt und zufällige Nonce
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt)?;

    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce)?;

    // Aus dem Passwort einen 32-Byte-Schlüssel ableiten
    // (wird beim Verlassen der Funktion mit Nullen überschrieben)
    let encryption_key = derive_file_key(password, &salt, &kdf)?;

    // Die Cipher überschreibt ihre Kopie des Schlüssels beim Freigeben
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_slice())?;

    // Klartext: privater Schlüssel (32 Bytes) + Nickname
    let plaintext = Zeroizing::new(
        [
            identity.signing_key.to_bytes().as_slice(),
            identity.nickname.as_bytes(),
        ]
            .concat(),
    );

    let ciphertext = cipher.encrypt(
        &XNonce::try_from(nonce.as_slice())?,
        Payload {
            msg: &plaintext,
            aad: &EncryptedIdentity::header_v2(&kdf, &salt, &nonce),
        },
    )?;

    Ok(EncryptedIdentity {
        format: IdentityFormat::V2,
        kdf,
        salt,
        nonce,
        ciphertext,
    })
}
