use crate::models::identity::Identity;
use std::fs;
use std::path::Path;

pub fn save_identity(
    path: &Path,
    identity: &Identity,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = Vec::new();

    data.extend_from_slice(b"NEXO1");

    // Nickname
    let nickname_bytes = identity.nickname.as_bytes();
    let nickname_length = nickname_bytes.len() as u16;

    data.extend_from_slice(&nickname_length.to_le_bytes());
    data.extend_from_slice(nickname_bytes);

    // Encrypted private key
    data.extend_from_slice(&identity.encrypted_private_key.salt);
    data.extend_from_slice(&identity.encrypted_private_key.nonce);
    data.extend_from_slice(&identity.encrypted_private_key.ciphertext);

    fs::write(path, data)?;

    Ok(())
}