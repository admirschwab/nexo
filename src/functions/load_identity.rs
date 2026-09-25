use crate::models::encrypted_private_key::EncryptedPrivateKey;
use crate::models::identity::Identity;
use std::fs;
use std::path::Path;

pub fn load_identity(
    path: &Path,
) -> Result<Identity, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;

    if data.len() < 7 {
        return Err("Identity file is too short".into());
    }

    if &data[0..5] != b"NEXO1" {
        return Err("Unknown identity file format".into());
    }

    let nickname_length =
        u16::from_le_bytes([data[5], data[6]]) as usize;

    let nickname_start = 7;
    let nickname_end = nickname_start + nickname_length;

    if data.len() < nickname_end + 40 {
        return Err("Identity file is corrupted".into());
    }

    let nickname = String::from_utf8(
        data[nickname_start..nickname_end].to_vec(),
    )?;

    let salt_start = nickname_end;
    let nonce_start = salt_start + 16;
    let ciphertext_start = nonce_start + 24;

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[salt_start..nonce_start]);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[nonce_start..ciphertext_start]);

    let ciphertext = data[ciphertext_start..].to_vec();

    if ciphertext.is_empty() {
        return Err("Identity file contains no encrypted private key".into());
    }

    let encrypted_private_key = EncryptedPrivateKey {
        salt,
        nonce,
        ciphertext,
    };

    Ok(Identity {
        nickname,
        encrypted_private_key,
    })
}